#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod encoding;
pub mod hashes;
pub mod receive;
pub mod send;
pub use bitcoin;

use bitcoin::{
    hashes::Hash,
    secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey},
    OutPoint, ScriptBuf, TxIn,
};

/// NUM Point used to prune key path spend in taproot
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpInputs {
    P2TR,
    P2WPKH,
    WrappedSegwit,
    P2PKH,
}

pub fn tag_txin(txin: &TxIn, script_pubkey: &ScriptBuf) -> Option<SpInputs> {
    use SpInputs::*;

    match (txin.witness.is_empty(), txin.script_sig.is_empty()) {
        // Wrapped Segwit
        (false, false) if script_pubkey.is_p2sh() => txin
            .script_sig
            .redeem_script()
            .filter(|script_pubkey| script_pubkey.is_p2wpkh())
            // if not P2SH-P2WPKH return None
            .map(|_| WrappedSegwit),
        // Native segwit
        (false, true) => {
            // P2WPKH
            if script_pubkey.is_p2wpkh() {
                Some(P2WPKH)
            } else {
                // P2TR
                script_pubkey
                    .is_p2tr()
                    .then(|| {
                        txin.witness
                            .taproot_control_block()
                            .filter(|control_block| control_block[1..33] == NUMS_H)
                            // if P2TR has no internal key return None
                            .map_or(Some(P2TR), |_| None)
                    })
                    .flatten()
            }
        }
        // No witness, legacy P2PKH
        (true, false) if script_pubkey.is_p2pkh() => Some(P2PKH),
        // All other cases
        _ => None,
    }
}

pub fn get_smallest_lexicographic_outpoint(outpoints: &[OutPoint]) -> [u8; 36] {
    // Find the outpoint with the smallest lexicographic order
    let smallest = outpoints
        .iter()
        .min_by(|a, b| {
            // Compare txids first
            let a_txid = a.txid.to_raw_hash();
            let b_txid = b.txid.to_raw_hash();

            // If txids are different, compare them
            match a_txid.as_byte_array().cmp(b_txid.as_byte_array()) {
                std::cmp::Ordering::Equal => {
                    // If txids are equal, compare vouts directly
                    let a_vout_bytes = a.vout.to_le_bytes();
                    let b_vout_bytes = b.vout.to_le_bytes();
                    a_vout_bytes.cmp(&b_vout_bytes)
                }
                other => other,
            }
        })
        .expect("cannot create silent payment script pubkey without outpoints");

    // Only allocate the result array once we have the smallest outpoint
    let mut result = [0u8; 36];
    result[..32].copy_from_slice(smallest.txid.to_raw_hash().as_byte_array());
    result[32..36].copy_from_slice(&smallest.vout.to_le_bytes());

    result
}

// Do not report coverage for this function as it is a wrapper around external lib function
// shared_secret_point
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn compute_shared_secret(sk: &SecretKey, pk: &PublicKey) -> PublicKey {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    // TODO: Update to use x_only_shared_secret
    ss_bytes[1..].copy_from_slice(&shared_secret_point(pk, sk));

    PublicKey::from_slice(&ss_bytes).expect("computationally unreachable: can only fail if public key is invalid in the first place or sk is")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        get_smallest_lexicographic_outpoint, tag_txin, Hash, ScriptBuf, SpInputs, TxIn, NUMS_H,
    };
    use bitcoin::{
        hex::test_hex_unwrap as hex, taproot::TAPROOT_ANNEX_PREFIX, OutPoint, Sequence, Txid,
        Witness,
    };

    #[test]
    fn test_tag_txin_p2sh_p2wpkh() {
        let script_pubkey = ScriptBuf::from_hex("a914809b71783f1b55eeadeb1678baef0c994adc425987")
            .expect("should succeed");
        // third input from testnet tx 65eb5594eda20b3a2437c2e2c28ba7633f0492cbb33f62ee31469b913ce8a5ca
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("1600146a721dcca372f3c17b2c649b2ba61aa0fda98a91")
                .expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "304402204ebf033caf3a1a210623e98b49acb41db2220c531843106d5c50736b144b15aa02201a006be1ebc2ffef0927d4458e3bb5e41e5abc7e44fc5ceb920049b46f87971101"
            ), hex!("02ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d")]),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(Some(SpInputs::WrappedSegwit), tagged_input);
    }

    #[test]
    fn test_tag_txin_p2sh_p2wsh() {
        let script_pubkey = ScriptBuf::from_hex("a914257014cec2f75c19367b2a6a0e08b9f304108e3b87")
            .expect("should succeed");
        // only input from mainnet tx 55c7c71c63b87478cd30d401e7ca5344a2e159dc8d6990df695c7e0cb2f82783
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "c57007980fabfd7c44895d8fc2c28c6ead93483b7c2bfec682ce0a3eaa4008ce"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_hex("220020973cfd44e60501c38320ab1105fb3ee3916d2952702e3c8cb4cbb7056aa6b47f")
                .unwrap(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[hex!(
                "0400473044022047ebba593cba4048da04316b9fb6c076d95d17175d7560edc93868a7d170767502203d0ce939ae462ca685a15f5fd3a64b7a1793cb10473665d5bedd3322c55a2b1001473044022022a8a0ae1f80934abb38d4f8c3febf6f5c5c43e7e70460aa71f9a895aaea4d950220023b8f4d2fd90abdbe6f80c9bcb2b38c7326e5e9e0f3b1ea25a5499d240cacb20169522103591da02bf7c80dc5d0edee4bbbfad7e58320785e3e54d4dab117152361f7002c21027ea2bc65ce49dcd748e4e41a0c8881be388b9182ad5e47579a0de0119803827b2103c5fdaf887f76119a73a7f738d5d4a451ff07bbbc83422c529452d8a36ae59e3953ae"
            )]),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(None, tagged_input);
    }

    #[test]
    fn test_tag_txin_p2tr() {
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

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(Some(SpInputs::P2TR), tagged_input);
    }

    #[test]
    fn test_tag_txin_p2tr_nums_point() {
        let script_pubkey = ScriptBuf::from_hex(
            "51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .expect("should succeed");
        let mut nums_in_witness = [0u8; 33];
        nums_in_witness[1..33].clone_from_slice(&NUMS_H);
        // Crafted P2TR Tx with NUMS point as internal key
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[
                hex!("02ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d"),
                hex!("02ae68d299cbb8ab99bf24c9af79a7b13d28ac8cd21f6f7f750300eda41a589a5d"),
                nums_in_witness.to_vec(),
                vec![TAPROOT_ANNEX_PREFIX],
            ]),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(None, tagged_input);
    }

    #[test]
    fn test_tag_txin_p2wpkh() {
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

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(Some(SpInputs::P2WPKH), tagged_input);
    }

    #[test]
    fn test_tag_txin_invalid_p2wpkh_input_with_non_empty_script_sig() {
        let script_pubkey = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");
        // Crafted example taking mainnet tx 091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe as template
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            // use script pubkey p2wpkh to catch mutations in tag_txin match arms
            script_sig: ScriptBuf::from_hex("1600146a721dcca372f3c17b2c649b2ba61aa0fda98a91").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[
                hex!("3044022025f63cdce46c749ff1953200b4fda615c7bbd6aa1717850c39297ce1087071ca0220675349fe9f9c6cf626f66abfd4ea1381b470a8315d1a8922d2573dc1410c661501"),
                hex!("03eb01a0190cb4d5da80878b20ff3823cc45b4fe55288393ee5d9f8a7f5eb65bbb"),
            ]),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(None, tagged_input);
    }

    #[test]
    fn test_tag_txin_p2pkh() {
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

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(Some(SpInputs::P2PKH), tagged_input);
    }

    #[test]
    fn test_tag_txin_p2pk() {
        let script_pubkey = ScriptBuf::from_hex("41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac")
            .expect("should succeed");
        // only input from mainnet tx e827a366ad4fc9a305e0901fe1eefc7e9fb8d70655a079877cf1ead0c3618ec0
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "1db6251a9afce7025a2061a19e63c700dffc3bec368bd1883decfac353357a9d"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(None, tagged_input);
    }

    #[test]
    fn test_tag_txin_p2sh_no_witness_script_sig_non_empty_spk_is_not_p2wpkh() {
        let script_pubkey = ScriptBuf::from_hex("a914748284390f9e263a4b766a75d0633c50426eb87587")
            .expect("should succeed");
        // Eleventh input from mainnet tx 30c239f3ae062c5f1151476005fd0057adfa6922de1b38d0f11eb657a8157b30
        let txin = TxIn {
            previous_output: OutPoint {
                txid: "450c309b70fb3f71b63b10ce60af17499bd21b1db39aa47b19bf22166ee67144"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae").expect("should succeed"),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let tagged_input = tag_txin(&txin, &script_pubkey);

        assert_eq!(None, tagged_input);
    }

    #[test]
    fn test_get_smallest_outpoint_different_txids_and_vouts() {
        let outpoints = vec![
            OutPoint {
                txid: Txid::from_slice(&[3u8; 32]).unwrap(),
                vout: 2,
            },
            OutPoint {
                txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                vout: 1,
            },
            OutPoint {
                txid: Txid::from_slice(&[5u8; 32]).unwrap(),
                vout: 3,
            },
        ];

        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [2u8; 36];
        expected_bytes[32..36].copy_from_slice(&1u32.to_le_bytes());

        assert_eq!(result, expected_bytes);
    }

    #[test]
    #[should_panic(expected = "cannot create silent payment script pubkey without outpoints")]
    fn test_get_smallest_outpoint_empty() {
        let outpoints: Vec<OutPoint> = vec![];
        get_smallest_lexicographic_outpoint(&outpoints);
    }

    // Additional test: same txid, different vouts
    #[test]
    fn test_get_smallest_outpoint_identical_txid_different_vouts() {
        let txid = Txid::from_slice(&[0u8; 32]).unwrap();
        let outpoints = vec![
            OutPoint { txid, vout: 10 },
            OutPoint { txid, vout: 2 },
            OutPoint { txid, vout: 5 },
        ];

        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [0u8; 36];
        expected_bytes[32..36].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_get_smallest_outpoint_same_vout_different_txid() {
        let outpoints = vec![
            OutPoint {
                txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                vout: 7,
            },
            OutPoint {
                txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                vout: 7,
            },
            OutPoint {
                txid: Txid::from_slice(&[3u8; 32]).unwrap(),
                vout: 7,
            },
        ];

        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [1u8; 36];
        expected_bytes[32..36].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_get_smallest_outpoint_edge_case_max_vout() {
        let outpoints = vec![
            OutPoint {
                txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                vout: u32::MAX,
            },
            OutPoint {
                txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                vout: u32::MIN,
            },
        ];

        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [1u8; 36];
        expected_bytes[..32].copy_from_slice(&[1u8; 32]);
        expected_bytes[32..36].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_get_smallest_outpoint_txid_takes_precedence() {
        let outpoints = vec![
            OutPoint {
                txid: Txid::from_slice(&[8u8; 32]).unwrap(),
                vout: 0,
            },
            OutPoint {
                txid: Txid::from_slice(&[5u8; 32]).unwrap(),
                vout: 100,
            },
        ];

        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [5u8; 36];
        expected_bytes[32..36].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_get_smallest_outpoint_txid_endianness_matters() {
        // big endian: 0x[00][00][00][01]
        // big endian: 0x[a1][b1][c1][d1]
        let mut txid_bytes_be = [0u8; 32];
        txid_bytes_be[0] = 1;

        // little endian: 0x[01][00][00][00]
        // little endian: 0x[a2][b2][c2][d2]
        let mut txid_bytes_le = [0u8; 32];
        txid_bytes_le[31] = 1;

        let outpoints = vec![
            OutPoint {
                txid: Txid::from_slice(&txid_bytes_be).unwrap(),
                vout: 1,
            },
            OutPoint {
                txid: Txid::from_slice(&txid_bytes_le).unwrap(),
                vout: 1,
            },
        ];

        // if Txid is big endian then: [a1] < [a2] => expected_bytes = txid_bytes_be
        // if Txid is little endian then: [d2] < [d1] => expected_bytes = txid_bytes_le
        let result = get_smallest_lexicographic_outpoint(&outpoints);

        let mut expected_bytes = [0u8; 36];
        expected_bytes[31] = 1;
        expected_bytes[32..36].copy_from_slice(&1u32.to_le_bytes());

        assert_eq!(result, expected_bytes);
    }
}
