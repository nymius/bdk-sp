use crate::hashes::{InputsHash, SharedSecretHash};
use std::collections::HashMap;

use bitcoin::{
    self,
    hashes::{Hash, HashEngine},
    key::Parity,
    secp256k1::{self, ecdh::shared_secret_point, PublicKey, Scalar, SecretKey},
    CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut, XOnlyPublicKey,
};

/// NUM Point used to prune key path spend in taproot
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug)]
pub enum PubKeyExtractionError {
    /// The input is not valid
    InvalidInput(&'static str),
    // Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
}

impl From<bitcoin::secp256k1::Error> for PubKeyExtractionError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

pub fn get_pubkey_from_input(
    txin: TxIn,
    script_pubkey: &ScriptBuf,
) -> Result<Option<PublicKey>, PubKeyExtractionError> {
    enum InputsForSharedSecretDerivation {
        P2TR,
        P2WPKH,
        WrappedSegwit,
        P2PKH,
        NotForSharedSecretDerivation,
    }
    use InputsForSharedSecretDerivation::*;

    let type_of_input_for_shared_secret_derivation = if !txin.witness.is_empty() {
        if !txin.script_sig.is_empty()
            && script_pubkey.is_p2sh()
            && txin
                .script_sig
                .redeem_script()
                .filter(|script| script.is_p2wpkh())
                .is_some()
        {
            WrappedSegwit
        } else if !txin.script_sig.is_empty() {
            NotForSharedSecretDerivation
        } else if script_pubkey.is_p2wpkh() {
            P2WPKH
        } else if script_pubkey.is_p2tr() {
            P2TR
        } else {
            NotForSharedSecretDerivation
        }
    } else if !txin.script_sig.is_empty() && script_pubkey.is_p2pkh() {
        P2PKH
    } else {
        NotForSharedSecretDerivation
    };

    match type_of_input_for_shared_secret_derivation {
        WrappedSegwit | P2WPKH => txin
            .witness
            .last()
            // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
            // not considered.
            .map(CompressedPublicKey::from_slice)
            .transpose()?
            .map_or(Err(PubKeyExtractionError::InvalidInput("")), |pubkey| {
                Ok(Some(PublicKey::from_slice(&pubkey.to_bytes()).unwrap()))
            }),
        P2TR => {
            if txin
                .witness
                .taproot_control_block()
                .filter(|control_block| control_block[1..33] == NUMS_H)
                .is_some()
            {
                Ok(None)
            } else {
                Ok(Some(
                    // NOTE: Only x only even taproot keys should be considered
                    XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])?
                        .public_key(Parity::Even),
                ))
            }
        }
        P2PKH => {
            let compressed_pubkey = txin
                .script_sig
                .into_bytes()
                // Is there a compressed pubkey somewhere?
                .windows(33)
                .last()
                // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
                // not considered.
                .map(CompressedPublicKey::from_slice)
                .transpose()?;

            Ok(compressed_pubkey
                .filter(|pubkey| {
                    <PubkeyHash as AsRef<[u8; 20]>>::as_ref(&pubkey.pubkey_hash())
                        == script_pubkey[3..23].as_bytes()
                })
                .map(|pubkey| PublicKey::from_slice(&pubkey.to_bytes()).unwrap()))
        }
        NotForSharedSecretDerivation => Ok(None),
    }
}

pub struct Scanner {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
    label_lookup: HashMap<PublicKey, (Scalar, u32)>,
}

#[derive(Debug)]
pub struct SpOutput {
    pub outpoint: OutPoint,
    pub tweak: Scalar,
    pub public_key: XOnlyPublicKey,
    pub label: Option<u32>,
}

impl Scanner {
    pub fn new(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
        label_lookup: HashMap<PublicKey, (Scalar, u32)>,
    ) -> Self {
        Scanner {
            scan_sk,
            spend_pk,
            label_lookup,
        }
    }

    pub fn scan_tx(&self, tx: &Transaction, prevouts: &[TxOut]) -> Vec<SpOutput> {
        assert_eq!(tx.input.len(), prevouts.len());

        let secp = secp256k1::Secp256k1::new();

        let input_pubkeys: Vec<PublicKey> = tx
            .input
            .clone()
            .into_iter()
            .zip(prevouts)
            .map(|(txin, prevout)| {
                let prevout_spk = prevout.script_pubkey.clone();
                get_pubkey_from_input(txin, &prevout_spk).unwrap_or_default()
            })
            .filter(|x| x.is_some())
            .flatten()
            .collect();

        let input_pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();

        #[allow(non_snake_case)]
        // NOTE: Remember to properly handle all these `unwrap`s
        let A_sum = PublicKey::combine_keys(&input_pubkey_refs).unwrap();
        let smallest_outpoint = tx
            .input
            .iter()
            .map(|txin| {
                let outpoint = txin.previous_output;
                let mut outpoint_bytes = [0u8; 36];
                outpoint_bytes[..32].copy_from_slice(outpoint.txid.to_raw_hash().as_byte_array());
                outpoint_bytes[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
                outpoint_bytes
            })
            .min()
            .unwrap();

        let input_hash = {
            let mut eng = InputsHash::engine();
            eng.input(&smallest_outpoint);
            eng.input(&A_sum.serialize());
            let hash = InputsHash::from_engine(eng);
            // NOTE: Why big endian bytes???
            Scalar::from_be_bytes(hash.to_byte_array())
                .expect("hash value greater than curve order")
        };

        // NOTE: Remember to properly handle all these `unwrap`s
        let partial_ecdh_shared_secret = A_sum.mul_tweak(&secp, &input_hash).unwrap();

        let ecdh_shared_secret = {
            let mut ss_bytes = [0u8; 65];
            ss_bytes[0] = 0x04;

            // Using `shared_secret_point` to ensure the multiplication is constant time
            ss_bytes[1..].copy_from_slice(&shared_secret_point(
                &partial_ecdh_shared_secret,
                &self.scan_sk,
            ));

            PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
        };

        let mut outputs_to_check = {
            let outputs_to_check_even = tx.output.iter().enumerate().filter_map(|(i, txout)| {
                let op = OutPoint {
                    vout: i as u32,
                    txid: tx.compute_txid(),
                };

                if txout.script_pubkey.is_p2tr() {
                    let xonly_pk =
                        XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..]).ok()?;

                    let pk = xonly_pk.public_key(Parity::Even);
                    Some((pk, op))
                } else {
                    None
                }
            });

            let outputs_to_check_odd = outputs_to_check_even
                .clone()
                .map(|(pk, op)| (pk.negate(&secp), op));

            outputs_to_check_even.chain(outputs_to_check_odd)
        };

        let mut sp_outputs_found = <Vec<SpOutput>>::new();
        let mut k = 0_u32;
        let mut loop_count = 0_u32;

        while k == loop_count {
            let t_k = {
                let mut eng = SharedSecretHash::engine();
                eng.input(&ecdh_shared_secret.serialize());
                eng.input(&k.to_le_bytes());
                let hash = SharedSecretHash::from_engine(eng);
                SecretKey::from_slice(&hash.to_byte_array()).unwrap()
            };

            #[allow(non_snake_case)]
            let T_k = t_k.public_key(&secp);

            #[allow(non_snake_case)]
            let P_k = self.spend_pk.combine(&T_k).unwrap();

            if let Some((pk, outpoint)) = outputs_to_check.find(|(pk, _)| P_k == *pk) {
                k += 1;
                sp_outputs_found.push(SpOutput {
                    outpoint,
                    tweak: t_k.into(),
                    public_key: XOnlyPublicKey::from(pk),
                    label: None,
                });
            }

            if let Some(sp_output) = outputs_to_check.find_map(|(pk, outpoint)| {
                let labeled_pk = pk.combine(&P_k.negate(&secp)).unwrap();
                self.label_lookup
                    .get(&labeled_pk)
                    .map(|(tweak, label)| SpOutput {
                        outpoint,
                        tweak: *tweak,
                        public_key: XOnlyPublicKey::from(pk),
                        label: Some(*label),
                    })
            }) {
                k += 1;
                sp_outputs_found.push(sp_output);
            }

            loop_count += 1;
        }

        sp_outputs_found
    }
}
