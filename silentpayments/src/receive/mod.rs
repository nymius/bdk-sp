pub use self::error::SpReceiveError;
use crate::{
    hashes::{InputsHash, SharedSecretHash},
    tag_txin, LexMin, SpInputs,
};

use bitcoin::{
    self,
    hashes::{Hash, HashEngine},
    key::{Parity, Secp256k1, TweakedPublicKey},
    secp256k1::{PublicKey, Scalar, SecretKey},
    Amount, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use std::collections::BTreeMap;

pub mod error;
pub mod scan;

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

pub fn extract_pubkey(txin: TxIn, script_pubkey: &ScriptBuf) -> Option<(SpInputs, PublicKey)> {
    use SpInputs::*;

    tag_txin(&txin, script_pubkey).and_then(|tag| match tag {
        WrappedSegwit | P2WPKH => {
            let maybe_pk = txin.witness.last().expect("already checked is not empty");
            bitcoin::PublicKey::from_slice(maybe_pk)
                .ok()
                .filter(|pubkey| pubkey.compressed)
                .map(|pk| (tag, pk.inner))
        }
        P2TR => XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])
            .ok()
            .map(|xonly_pk| (tag, xonly_pk.public_key(Parity::Even))),
        P2PKH => txin
            .script_sig
            .into_bytes()
            .windows(33)
            .rev()
            .find_map(|slice| {
                bitcoin::PublicKey::from_slice(slice)
                    .ok()
                    .filter(|pubkey| {
                        <PubkeyHash as AsRef<[u8; 20]>>::as_ref(&pubkey.pubkey_hash())
                            == script_pubkey[3..23].as_bytes()
                    })
                    .map(|pk| (tag, pk.inner))
            }),
    })
}

pub fn scan_txouts(
    spend_pk: PublicKey,
    label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
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
            SecretKey::from_slice(&hash.to_byte_array())
                .expect("computationally unreachable: only if hash value greater than curve order")
        };

        #[allow(non_snake_case)]
        let T_k = t_k.public_key(&secp);

        #[allow(non_snake_case)]
            let P_k = spend_pk.combine(&T_k)
                .expect("computationally unreachable: can only fail if ecdh_hash = -spend_sk (DLog of spend_pk), but ecdh_hash is the output of a hash function");

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
            if let Some((label_tweak, label)) = label_lookup.get(&pk_m) {
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
/// The derivation_order is a parameter to produce the silent payment script pubkey obtained
/// after adding derivation_order of silent payment outputs directed to the same silent
/// payment code.
/// The optional maybe_label_into_ecc can be used to get the script pubkey from a labelled silent
/// payment where the label is the preimage of hash(label) * G, where G is the generator point
/// of secp256k1.
/// Use in the context of CBF to compute posible script pubkeys without knowledge of the
/// transaction from which the ecdh shared secret is produced.
pub fn get_silentpayment_script_pubkey(
    spend_pk: &PublicKey,
    ecdh_shared_secret: &PublicKey,
    derivation_order: u32,
    maybe_label_point: Option<&PublicKey>,
) -> ScriptBuf {
    let secp = Secp256k1::new();

    let t_k = {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh_shared_secret.serialize());
        // Just produce spks for the first possible
        // silent payment in a tx
        eng.input(&derivation_order.to_be_bytes());
        let hash = SharedSecretHash::from_engine(eng);
        SecretKey::from_slice(&hash.to_byte_array())
            .expect("computationally unreachable: only if hash value greater than curve order")
    };

    #[allow(non_snake_case)]
    let T_k = t_k.public_key(&secp);

    #[allow(non_snake_case)]
        let mut P_k = spend_pk.combine(&T_k)
            .expect("computationally unreachable: can only fail if ecdh_hash = -spend_sk (DLog of spend_pk), but ecdh_hash is the output of a hash function");

    P_k = if let Some(label_point) = maybe_label_point {
        P_k.combine(label_point)
                .expect("computationally unreachable: can only fail if label (scalar) = -spend_sk (DLog of spend_pk), but label (scalar) is the output of a hash function")
    } else {
        P_k
    };

    let (x_only_key, _) = P_k.x_only_public_key();

    let assumed_tweaked_pk = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);

    ScriptBuf::new_p2tr_tweaked(assumed_tweaked_pk)
}

pub fn compute_tweak_data(
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<PublicKey, SpReceiveError> {
    let secp = Secp256k1::verification_only();

    let mut input_pubkeys = <Vec<PublicKey>>::new();
    let mut lex_min = LexMin::default();
    for (txin, prevout) in tx.input.iter().zip(prevouts) {
        lex_min.update(&txin.previous_output);
        // NOTE: Public keys which couldn't be extracted will be ignored
        if let Some((_, key)) = extract_pubkey(txin.clone(), &prevout.script_pubkey) {
            input_pubkeys.push(key)
        }
    }

    let input_pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();

    #[allow(non_snake_case)]
    // NOTE: cannot ignore malicious crafting of transaction with input public keys that cancel
    // themselves
    let A_sum = PublicKey::combine_keys(&input_pubkey_refs)?;

    let input_hash = {
        let mut eng = InputsHash::engine();
        eng.input(&lex_min.bytes()?);
        eng.input(&A_sum.serialize());
        let hash = InputsHash::from_engine(eng);
        // NOTE: Why big endian bytes??? Doesn't matter. Look at: https://github.com/rust-bitcoin/rust-bitcoin/issues/1896
        Scalar::from_be_bytes(hash.to_byte_array()).expect("hash value greater than curve order")
    };

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::extract_pubkey;
    use crate::SpInputs;
    use bitcoin::{
        hex::test_hex_unwrap as hex,
        secp256k1::{self, PublicKey},
        OutPoint, ScriptBuf, Sequence, TxIn, Witness,
    };
    use std::str::FromStr;


    #[test]
    fn test_extract_pubkey_wrapped_segwit_ok() {
        let script_pubkey = ScriptBuf::from_hex("a914809b71783f1b55eeadeb1678baef0c994adc425987")
            .expect("should succeed");
        // third input from testnet tx 65eb5594eda20b3a2437c2e2c28ba7633f0492cbb33f62ee31469b913ce8a5ca
        let txin = TxIn {
            previous_output: OutPoint{
                txid: "04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("1600146a721dcca372f3c17b2c649b2ba61aa0fda98a91")
                .unwrap(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "304402204ebf033caf3a1a210623e98b49acb41db2220c531843106d5c50736b144b15aa02201a006be1ebc2ffef0927d4458e3bb5e41e5abc7e44fc5ceb920049b46f87971101"
            ), hex!("02ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d")]),
        };

        let expected_pubkey = PublicKey::from_str(
            "02ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d",
        )
        .expect("should work");
        let maybe_pubkey = extract_pubkey(txin, &script_pubkey);

        assert!(maybe_pubkey.is_some());

        let (input_type, parsed_pubkey) = maybe_pubkey.expect("is some");

        assert_eq!(SpInputs::WrappedSegwit, input_type);

        assert_eq!(expected_pubkey, parsed_pubkey);
    }

    #[test]
    fn test_extract_pubkey_p2wpkh_ok() {
        let script_pubkey = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");
        // only input from mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[
                hex!("3044022025f63cdce46c749ff1953200b4fda615c7bbd6aa1717850c39297ce1087071ca0220675349fe9f9c6cf626f66abfd4ea1381b470a8315d1a8922d2573dc1410c661501"),
                hex!("03eb01a0190cb4d5da80878b20ff3823cc45b4fe55288393ee5d9f8a7f5eb65bbb"),
            ]),
        };

        let expected_pubkey = PublicKey::from_str(
            "03eb01a0190cb4d5da80878b20ff3823cc45b4fe55288393ee5d9f8a7f5eb65bbb",
        )
        .expect("should succeed");
        let maybe_pubkey = extract_pubkey(txin, &script_pubkey);

        assert!(maybe_pubkey.is_some());

        let (input_type, parsed_pubkey) = maybe_pubkey.expect("is some");

        assert_eq!(SpInputs::P2WPKH, input_type);

        assert_eq!(expected_pubkey, parsed_pubkey);
    }

    #[test]
    fn test_extract_pubkey_p2tr_ok() {
        let script_pubkey = ScriptBuf::from_hex(
            "51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .expect("should succeed");
        // only input from mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae01"
            )]),
        };

        let expected_pubkey = PublicKey::from_str(
            "020f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .expect("should succeed");

        let maybe_pubkey = extract_pubkey(txin, &script_pubkey);

        assert!(maybe_pubkey.is_some());

        let (input_type, parsed_pubkey) = maybe_pubkey.expect("is some");

        assert_eq!(SpInputs::P2TR, input_type);

        assert_eq!(expected_pubkey, parsed_pubkey);
    }

    #[test]
    fn test_extract_pubkey_p2pkh_ok() {
        let script_pubkey =
            ScriptBuf::from_hex("76a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac")
                .expect("should succeed");
        // only input from mainnet tx 4316fe7be359937317f42ffaf05ab02554297fb83096a0beb985a25f9e338215
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "40e331b67c0fe7750bb3b1943b378bf702dce86124dc12fa5980f975db7ec930"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_hex("473044022076baac422976af25b32479ccb81df8a2d7f4f73cfb2ff98cfe10241feefdb43702204c08a9fc646150a9aceb3ebc26344e1596ddd6b7bc8aa44cb116a3adca173e3701210360a953b3da3f5cc0ec246a99411c19916fab7e72b59e105955b6e3e9d3a44773").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let expected_pubkey = PublicKey::from_str(
            "0360a953b3da3f5cc0ec246a99411c19916fab7e72b59e105955b6e3e9d3a44773",
        )
        .expect("should succeed");
        let maybe_pubkey = extract_pubkey(txin, &script_pubkey);

        assert!(maybe_pubkey.is_some());

        let (input_type, parsed_pubkey) = maybe_pubkey.expect("is some");

        assert_eq!(SpInputs::P2PKH, input_type);

        assert_eq!(expected_pubkey, parsed_pubkey);
    }

    #[test]
    fn test_extract_pubkey_malleated_p2pkh_ok() {
        let script_pubkey =
            ScriptBuf::from_hex("76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac")
                .expect("should succeed");
        // only input from mainnet tx 4316fe7be359937317f42ffaf05ab02554297fb83096a0beb985a25f9e338215
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("0075473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let expected_pubkey = PublicKey::from_str(
            "03782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
        )
        .expect("should succeed");

        let maybe_pubkey = extract_pubkey(txin, &script_pubkey);

        assert!(maybe_pubkey.is_some());

        let (input_type, parsed_pubkey) = maybe_pubkey.expect("is some");

        assert_eq!(SpInputs::P2PKH, input_type);

        assert_eq!(expected_pubkey, parsed_pubkey);
    }

    #[test]
    fn test_extract_pubkey_wrapped_segwit_invalid_key() {
        let script_pubkey = ScriptBuf::from_hex("a914809b71783f1b55eeadeb1678baef0c994adc425987")
            .expect("should succeed");
        // crafted using third input in testnet tx 65eb5594eda20b3a2437c2e2c28ba7633f0492cbb33f62ee31469b913ce8a5ca as template
        let txin = TxIn {
            previous_output: OutPoint{
                txid: "04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("1600146a721dcca372f3c17b2c649b2ba61aa0fda98a91")
                .unwrap(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "304402204ebf033caf3a1a210623e98b49acb41db2220c531843106d5c50736b144b15aa02201a006be1ebc2ffef0927d4458e3bb5e41e5abc7e44fc5ceb920049b46f87971101"
            ), secp256k1::constants::ZERO.to_vec()]),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }

    #[test]
    fn test_extract_pubkey_p2wpkh_invalid_key() {
        let script_pubkey = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");
        // crafted using the only input from mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe as template
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[
                hex!("3044022025f63cdce46c749ff1953200b4fda615c7bbd6aa1717850c39297ce1087071ca0220675349fe9f9c6cf626f66abfd4ea1381b470a8315d1a8922d2573dc1410c661501"),
                secp256k1::constants::ZERO.to_vec()
            ]),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }

    #[test]
    fn test_extract_pubkey_p2tr_invalid_key() {
        let script_pubkey = ScriptBuf::from_hex(
            "51200000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("should succeed");
        // crafted using only input from mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe as template
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae01"
            )]),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }

    #[test]
    fn test_extract_pubkey_p2pkh_invalid_key() {
        let script_pubkey =
            ScriptBuf::from_hex("76a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac")
                .expect("should succeed");
        // only input from mainnet tx 4316fe7be359937317f42ffaf05ab02554297fb83096a0beb985a25f9e338215
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "40e331b67c0fe7750bb3b1943b378bf702dce86124dc12fa5980f975db7ec930"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_hex("473044022076baac422976af25b32479ccb81df8a2d7f4f73cfb2ff98cfe10241feefdb43702204c08a9fc646150a9aceb3ebc26344e1596ddd6b7bc8aa44cb116a3adca173e370121000000000000000000000000000000000000000000000000000000000000000000").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }

    #[test]
    fn test_extract_pubkey_wrapped_segwit_uncompressed() {
        let script_pubkey = ScriptBuf::from_hex("a914809b71783f1b55eeadeb1678baef0c994adc425987")
            .expect("should succeed");
        // crafted using third input from testnet tx 65eb5594eda20b3a2437c2e2c28ba7633f0492cbb33f62ee31469b913ce8a5ca as template
        let txin = TxIn {
            previous_output: OutPoint{
                txid: "04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("1600146a721dcca372f3c17b2c649b2ba61aa0fda98a91")
                .unwrap(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "304402204ebf033caf3a1a210623e98b49acb41db2220c531843106d5c50736b144b15aa02201a006be1ebc2ffef0927d4458e3bb5e41e5abc7e44fc5ceb920049b46f87971101"
            // notice uncompressed public key here, at the end of the witness
            ), hex!("04ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d6a7210f279e3be22089aef2e29cf359a7eb0067d8caebae4298c5bec56ca41c2")]),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }

    #[test]
    fn test_extract_pubkey_p2wpkh_uncompressed() {
        let script_pubkey = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");
        // crafted using the only input from mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe as template
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[
                hex!("3044022025f63cdce46c749ff1953200b4fda615c7bbd6aa1717850c39297ce1087071ca0220675349fe9f9c6cf626f66abfd4ea1381b470a8315d1a8922d2573dc1410c661501"),
                hex!("04eb01a0190cb4d5da80878b20ff3823cc45b4fe55288393ee5d9f8a7f5eb65bbb8ac7e2a9044b74ce6284ebb08a92ebe489c27b43e542355e783b661b62ed76fd"),
            ]),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }
    #[test]
    fn test_extract_pubkey_malleated_p2pkh_wrong_pubkey_hash() {
        // Use a not matching script pubkey to make the pubkey hash differ
        let script_pubkey =
            ScriptBuf::from_hex("76a914b675771222403e064d9fb4d676fcfef47585b07f88ac")
                .expect("should succeed");
        // only input from mainnet tx 4316fe7be359937317f42ffaf05ab02554297fb83096a0beb985a25f9e338215
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("0075473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        assert!(extract_pubkey(txin, &script_pubkey).is_none());
    }
}
