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

#[derive(Debug, Clone, Copy)]
pub enum SpInputs {
    P2TR,
    P2WPKH,
    WrappedSegwit,
    P2PKH,
}

pub fn tag_txin(txin: &TxIn, script_pubkey: &ScriptBuf) -> Option<SpInputs> {
    use SpInputs::*;

    if !txin.witness.is_empty() {
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
    use super::*;
    use bitcoin::OutPoint;
    use bitcoin::Txid;

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
