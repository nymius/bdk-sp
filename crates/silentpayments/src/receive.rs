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
pub enum SpReceiveError {
    /// The input is not valid for silent payment shared secret derivation
    PubKeyExtractionError(&'static str),
    /// Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
}

impl From<bitcoin::secp256k1::Error> for SpReceiveError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl std::fmt::Display for SpReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpReceiveError::PubKeyExtractionError(e) => {
                write!(f, "Silent payment receive error: {e}")
            }
            SpReceiveError::Secp256k1Error(e) => write!(f, "Silent payment receive error: {e}"),
        }
    }
}

impl std::error::Error for SpReceiveError {}

pub fn extract_pubkey(
    txin: TxIn,
    script_pubkey: &ScriptBuf,
) -> Result<Option<PublicKey>, SpReceiveError> {
    enum SpInputs {
        P2TR,
        P2WPKH,
        WrappedSegwit,
        P2PKH,
    }

    use SpInputs::*;

    let input_type = if !txin.witness.is_empty() {
        if !txin.script_sig.is_empty()
            && script_pubkey.is_p2sh()
            && txin
                .script_sig
                .redeem_script()
                .filter(|script| script.is_p2wpkh())
                .is_some()
        {
            Some(WrappedSegwit)
        } else if !txin.script_sig.is_empty() {
            None
        } else if script_pubkey.is_p2wpkh() {
            Some(P2WPKH)
        } else if script_pubkey.is_p2tr() {
            if txin
                .witness
                .taproot_control_block()
                .filter(|control_block| control_block[1..33] == NUMS_H)
                .is_some()
            {
                None
            } else {
                Some(P2TR)
            }
        } else {
            None
        }
    } else if !txin.script_sig.is_empty() && script_pubkey.is_p2pkh() {
        Some(P2PKH)
    } else {
        None
    };

    input_type
        .map(|x| match x {
            WrappedSegwit | P2WPKH => txin
                .witness
                .last()
                // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
                // not considered.
                .map(CompressedPublicKey::from_slice)
                .transpose()?
                .map_or(
                    Err(SpReceiveError::PubKeyExtractionError(
                        "Public key extraction from TxOut witness failed",
                    )),
                    |pubkey| Ok(PublicKey::from_slice(&pubkey.to_bytes())?),
                ),
            P2TR => {
                Ok(
                    // NOTE: Only x only even taproot keys should be considered
                    XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])?
                        .public_key(Parity::Even),
                )
            }
            P2PKH => {
                txin.script_sig
                    .into_bytes()
                    .windows(33)
                    .last()
                    // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
                    // not considered.
                    .map(CompressedPublicKey::from_slice)
                    .transpose()?
                    .filter(|pubkey| {
                        <PubkeyHash as AsRef<[u8; 20]>>::as_ref(&pubkey.pubkey_hash())
                            == script_pubkey[3..23].as_bytes()
                    })
                    .map_or(
                        Err(SpReceiveError::PubKeyExtractionError(
                            "Public key extraction from TxOut script signature failed",
                        )),
                        |pubkey| Ok(PublicKey::from_slice(&pubkey.to_bytes())?),
                    )
            }
        })
        .transpose()
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

    pub fn scan_tx(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<Vec<SpOutput>, SpReceiveError> {
        assert_eq!(tx.input.len(), prevouts.len());

        let secp = secp256k1::Secp256k1::new();

        let input_pubkeys = tx
            .input
            .clone()
            .into_iter()
            .zip(prevouts)
            .filter_map(|(txin, prevout)| extract_pubkey(txin, &prevout.script_pubkey).transpose())
            .collect::<Result<Vec<PublicKey>, SpReceiveError>>()?;

        let input_pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();

        #[allow(non_snake_case)]
        // NOTE: cannot ignore malicious crafting of transaction with input public keys that cancel
        // themselves
        let A_sum = PublicKey::combine_keys(&input_pubkey_refs)?;
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
            .expect("transaction should have inputs");

        let input_hash = {
            let mut eng = InputsHash::engine();
            eng.input(&smallest_outpoint);
            eng.input(&A_sum.serialize());
            let hash = InputsHash::from_engine(eng);
            // NOTE: Why big endian bytes??? Doesn't matter. Look at: https://github.com/rust-bitcoin/rust-bitcoin/issues/1896
            Scalar::from_be_bytes(hash.to_byte_array())
                .expect("hash value greater than curve order")
        };

        let partial_ecdh_shared_secret = A_sum.mul_tweak(&secp, &input_hash)?;

        let ecdh_shared_secret = {
            let mut ss_bytes = [0u8; 65];
            ss_bytes[0] = 0x04;

            // Using `shared_secret_point` to ensure the multiplication is constant time
            // TODO: Update to use x_only_shared_secret
            ss_bytes[1..].copy_from_slice(&shared_secret_point(
                &partial_ecdh_shared_secret,
                &self.scan_sk,
            ));

            PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
        };

        let outputs_to_check: Vec<(PublicKey, OutPoint)> = {
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

            outputs_to_check_even
                .chain(outputs_to_check_odd)
                .collect::<Vec<(PublicKey, OutPoint)>>()
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
                SecretKey::from_slice(&hash.to_byte_array()).expect(
                    "computationally unreachable: only if hash value greater than curve order",
                )
            };

            #[allow(non_snake_case)]
            let T_k = t_k.public_key(&secp);

            #[allow(non_snake_case)]
            let P_k = self.spend_pk.combine(&T_k)
                .expect("computationally unreachable: can only fail if t_k = -spend_sk (DLog of spend_pk), but t_k is the output of a hash function");

            if let Some((pk, outpoint)) = outputs_to_check.iter().find(|(pk, _)| P_k == *pk) {
                k += 1;
                sp_outputs_found.push(SpOutput {
                    outpoint: *outpoint,
                    tweak: t_k.into(),
                    public_key: XOnlyPublicKey::from(*pk),
                    label: None,
                });
            } else {
                for (pk, outpoint) in outputs_to_check.iter() {
                    // NOTE: If labeled_pk = 0 or is larger or equal to the secp256k1 group order,
                    // ignore?
                    if let Ok(labeled_pk) = pk.combine(&P_k.negate(&secp)) {
                        if let Some(found_output) =
                            self.label_lookup
                                .get(&labeled_pk)
                                .map(|(tweak, label)| SpOutput {
                                    outpoint: *outpoint,
                                    tweak: *tweak,
                                    public_key: XOnlyPublicKey::from(*pk),
                                    label: Some(*label),
                                })
                        {
                            k += 1;
                            sp_outputs_found.push(found_output);
                            break;
                        }
                    }
                }
            }

            loop_count += 1;
        }

        Ok(sp_outputs_found)
    }
}
