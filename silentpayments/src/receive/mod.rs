pub mod error;

pub use self::error::SpReceiveError;
use crate::hashes::{InputsHash, SharedSecretHash};
use std::collections::BTreeMap;

use bitcoin::{
    self,
    hashes::{Hash, HashEngine},
    key::{Parity, Secp256k1, TweakedPublicKey},
    secp256k1::{ecdh::shared_secret_point, PublicKey, Scalar, SecretKey},
    Amount, CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    XOnlyPublicKey,
};

/// NUM Point used to prune key path spend in taproot
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

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
    label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SpOut {
    pub outpoint: OutPoint,
    pub tweak: SecretKey,
    pub xonly_pubkey: XOnlyPublicKey,
    pub amount: Amount,
    pub label: Option<u32>,
}

impl PartialOrd for SpOut {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SpOut {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.outpoint.cmp(&other.outpoint)
    }
}

impl From<&SpOut> for TxOut {
    fn from(spout: &SpOut) -> Self {
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(spout.xonly_pubkey);
        TxOut {
            value: spout.amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked_pubkey),
        }
    }
}

impl Scanner {
    pub fn new(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
        label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
    ) -> Self {
        Self {
            scan_sk,
            spend_pk,
            label_lookup,
        }
    }

    pub fn compute_tweak_data(
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<PublicKey, SpReceiveError> {
        let secp = Secp256k1::verification_only();

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

        Ok(A_sum.mul_tweak(&secp, &input_hash)?)
    }

    // NOTE: This method was extracted from the original scan_tx to avoid very complex type in the
    // return type of scan_tx (Result<Vec<Result<SpOut, SpReceiveError>>, SpReceiveError>) an also
    // allow indexers apply txouts of a partially scanned transaction. If scan_txout fails for some
    // of them, the correctly scanned will still be indexed
    pub fn compute_shared_secret(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<PublicKey, SpReceiveError> {
        assert_eq!(tx.input.len(), prevouts.len());

        let partial_ecdh_shared_secret = Self::compute_tweak_data(tx, prevouts)?;

        let mut ss_bytes = [0u8; 65];
        ss_bytes[0] = 0x04;

        // Using `shared_secret_point` to ensure the multiplication is constant time
        // TODO: Update to use x_only_shared_secret
        ss_bytes[1..].copy_from_slice(&shared_secret_point(
            &partial_ecdh_shared_secret,
            &self.scan_sk,
        ));

        Ok(PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve"))
    }

    pub fn scan_tx(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<Vec<SpOut>, SpReceiveError> {
        let ecdh_shared_secret = self.compute_shared_secret(tx, prevouts)?;
        self.scan_txouts(tx, ecdh_shared_secret)
    }

    pub fn scan_txouts(
        &self,
        tx: &Transaction,
        ecdh_shared_secret: PublicKey,
    ) -> Result<Vec<SpOut>, SpReceiveError> {
        let secp = Secp256k1::new();
        let txid: Txid = tx.compute_txid();
        let mut outputs_to_check = tx
            .output
            .iter()
            .filter(|x| x.script_pubkey.is_p2tr())
            .enumerate()
            .flat_map(|(idx, txout)| {
                let xonly_pubkey = XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
                    .expect("p2tr script");
                [Parity::Even, Parity::Odd].into_iter().map(move |parity| {
                    (
                        OutPoint::new(txid, idx as u32),
                        xonly_pubkey.public_key(parity),
                        txout.value,
                    )
                })
            })
            .collect::<Vec<(OutPoint, PublicKey, Amount)>>();

        let mut matched_tweaks = 0_u32;
        let mut spouts_found = <Vec<SpOut>>::new();

        loop {
            let t_k = {
                let mut eng = SharedSecretHash::engine();
                eng.input(&ecdh_shared_secret.serialize());
                eng.input(&matched_tweaks.to_be_bytes());
                let hash = SharedSecretHash::from_engine(eng);
                SecretKey::from_slice(&hash.to_byte_array()).expect(
                    "computationally unreachable: only if hash value greater than curve order",
                )
            };

            #[allow(non_snake_case)]
            let T_k = t_k.public_key(&secp);

            #[allow(non_snake_case)]
            let P_k = self.spend_pk.combine(&T_k).expect("computationally unreachable: can only fail if ecdh_hash = -spend_sk (DLog of spend_pk), but ecdh_hash is the output of a hash function");

            #[allow(non_snake_case)]
            let neg_P_k = P_k.negate(&secp);

            let mut i = 0;
            let mut spouts_found_with_tweak = <Vec<SpOut>>::new();
            while i < outputs_to_check.len() {
                let (outpoint, pubkey, amount) = outputs_to_check[i];
                let (xonly_pubkey, _parity) = pubkey.x_only_public_key();
                let spout = SpOut {
                    outpoint,
                    tweak: t_k,
                    xonly_pubkey,
                    amount,
                    label: None,
                };
                if P_k == pubkey {
                    spouts_found_with_tweak.push(spout);
                    outputs_to_check.remove(i);
                    continue;
                }

                let pk_m = pubkey.combine(&neg_P_k)?;
                if let Some((label_tweak, label)) = self.label_lookup.get(&pk_m) {
                    spouts_found_with_tweak.push(SpOut {
                        tweak: t_k.add_tweak(label_tweak)?,
                        label: Some(*label),
                        ..spout
                    });
                    outputs_to_check.remove(i);
                    continue;
                }

                i += 1;
            }

            if !spouts_found_with_tweak.is_empty() {
                spouts_found.extend(spouts_found_with_tweak);
                matched_tweaks += 1;
                continue;
            }

            break;
        }

        Ok(spouts_found)
    }

    /// Get the script pubkey for silent payments derived from the current set of scan and spend
    /// public key, combined with the elliptic curve diffie hellman provided.
    /// The already_found_count is a parameter to produce the silent payment script pubkey obtained
    /// after adding alread_found_count of silent payment outputs directed to the same silent
    /// payment code.
    /// The optional maybe_label_into_ecc can be used to get the script pubkey from a labelled silent
    /// payment where the label is the preimage of hash(label) * G, where G is the generator point
    /// of secp256k1.
    /// Use in the context of CBF to compute posible script pubkeys without knowledge of the
    /// transaction from which the ecdh shared secret is produced.
    pub fn sp_spk_from_ecdh(
        &self,
        ecdh_shared_secret: PublicKey,
        already_found_count: u32,
        maybe_label_into_ecc: Option<PublicKey>,
    ) -> ScriptBuf {
        let secp = Secp256k1::new();

        let t_k = {
            let mut eng = SharedSecretHash::engine();
            eng.input(&ecdh_shared_secret.serialize());
            // Just produce spks for the first possible
            // silent payment in a tx
            eng.input(&already_found_count.to_be_bytes());
            let hash = SharedSecretHash::from_engine(eng);
            SecretKey::from_slice(&hash.to_byte_array())
                .expect("computationally unreachable: only if hash value greater than curve order")
        };

        #[allow(non_snake_case)]
        let T_k = t_k.public_key(&secp);

        #[allow(non_snake_case)]
        let mut P_k = self.spend_pk.combine(&T_k)
            .expect("computationally unreachable: can only fail if ecdh_hash = -spend_sk (DLog of spend_pk), but ecdh_hash is the output of a hash function");

        P_k = if let Some(label_into_ecc) = maybe_label_into_ecc {
            P_k.combine(&label_into_ecc)
                .expect("computationally unreachable: can only fail if label (scalar) = -spend_sk (DLog of spend_pk), but label (scalar) is the output of a hash function")
        } else {
            P_k
        };

        let (x_only_key, _) = P_k.x_only_public_key();

        let assumed_tweaked_pk = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);

        ScriptBuf::new_p2tr_tweaked(assumed_tweaked_pk)
    }
}
