pub mod bip32;
pub mod bip352;
pub mod error;
pub mod psbt;

use crate::{
    compute_shared_secret,
    encoding::SilentPaymentCode,
    hashes::{InputsHash, SharedSecretHash},
    send::error::SpSendError,
};

use bitcoin::{
    hashes::{Hash, HashEngine},
    key::{Parity, Secp256k1},
    secp256k1::{PublicKey, Scalar, SecretKey},
    ScriptBuf, XOnlyPublicKey,
};

use std::collections::HashMap;

pub fn create_silentpayment_partial_secret(
    smallest_outpoint_bytes: &[u8; 36],
    spks_with_keys: &[(ScriptBuf, SecretKey)],
) -> Result<SecretKey, SpSendError> {
    let secp = Secp256k1::new();

    let available_keys = spks_with_keys
        .iter()
        .cloned()
        .filter_map(|(spk, sk)| {
            if spk.is_p2tr() {
                let (_, parity) = sk.x_only_public_key(&secp);
                if parity == Parity::Odd {
                    Some(sk.negate())
                } else {
                    Some(sk)
                }
            } else if spk.is_p2pkh() || spk.is_p2sh() || spk.is_p2wpkh() {
                Some(sk)
            } else {
                None
            }
        })
        .collect::<Vec<SecretKey>>();

    if available_keys.is_empty() {
        return Err(SpSendError::MissingInputsForSharedSecretDerivation);
    }

    // Use first derived_secret key to initialize a_sum
    let mut a_sum = available_keys[0];
    // Then skip first element to avoid reuse
    for sk in available_keys.iter().skip(1) {
        a_sum = a_sum.add_tweak(&Scalar::from(*sk))?;
    }

    #[allow(non_snake_case)]
    let A_sum = a_sum.public_key(&secp);

    let input_hash = {
        let mut eng = InputsHash::engine();
        eng.input(smallest_outpoint_bytes);
        eng.input(&A_sum.serialize());
        let hash = InputsHash::from_engine(eng);
        // NOTE: Why big endian bytes??? Doesn't matter. Look at: https://github.com/rust-bitcoin/rust-bitcoin/issues/1896
        Scalar::from_be_bytes(hash.to_byte_array()).expect("hash value greater than curve order")
    };

    Ok(a_sum
        .mul_tweak(&input_hash)
        .expect("computationally unreachable: can only fail if a_sum is invalid or input_hash is"))
}

pub fn create_silentpayment_scriptpubkeys(
    partial_secret: SecretKey,
    outputs: &[SilentPaymentCode],
) -> Result<HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>, SpSendError> {
    let secp = Secp256k1::new();

    // Cache to avoid recomputing ecdh shared secret for each B_scan and track the k to get the
    // shared secret hash for each output
    let mut shared_secret_cache = <HashMap<PublicKey, (u32, PublicKey)>>::new();

    let mut payments = <HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>>::new();
    for sp_code @ SilentPaymentCode { scan, spend, .. } in outputs.iter() {
        let (k, shared_secret) =
            if let Some((k, ecdh_shared_secret)) = shared_secret_cache.get(scan) {
                (*k, *ecdh_shared_secret)
            } else {
                (0u32, compute_shared_secret(&partial_secret, scan))
            };

        shared_secret_cache.insert(*scan, (k + 1, shared_secret));

        #[allow(non_snake_case)]
        let T_k = {
            let mut eng = SharedSecretHash::engine();
            eng.input(&shared_secret.serialize());
            eng.input(&k.to_be_bytes());
            let hash = SharedSecretHash::from_engine(eng);
            let t_k = SecretKey::from_slice(&hash.to_byte_array())
                .expect("computationally unreachable: only if hash value greater than curve order");
            t_k.public_key(&secp)
        };

        #[allow(non_snake_case)]
        let P_mn = spend.combine(&T_k)
            .expect("computationally unreachable: can only fail if t_k = -spend_sk (DLog of spend), but t_k is the output of a hash function");
        // NOTE: Should we care about parity here? No. Look at: https://gist.github.com/sipa/c9299811fb1f56abdcd2451a8a078d20
        let (x_only_pubkey, _) = P_mn.x_only_public_key();

        if let Some(pubkeys) = payments.get_mut(sp_code) {
            pubkeys.push(x_only_pubkey);
        } else {
            payments.insert(sp_code.clone(), vec![x_only_pubkey]);
        }
    }

    Ok(payments)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use std::str::FromStr;

    const SCAN_PK_1: &str = "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b";
    const SPEND_PK_1: &str = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
    const SCAN_PK_2: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const SPEND_PK_2: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const PARTIAL_SECRET_1: &str =
        "d5c68eccb3ddd0fab0bf504209b8b6ce3f51832beb136a5f91ade54bc059f9b8";
    const PARTIAL_SECRET_2: &str =
        "e9b700555d60a8c4a874128c68b07ed7234248910db80d073d298e058df1786f";

    fn setup_test_data() -> (SecretKey, Vec<SilentPaymentCode>) {
        let partial_secret = SecretKey::from_str(PARTIAL_SECRET_1).expect("reading from constant");

        // Create some test SilentPaymentCodes
        let scan_1 = PublicKey::from_str(SCAN_PK_1).expect("reading from constant");
        let spend_1 = PublicKey::from_str(SPEND_PK_1).expect("reading from constant");

        let scan_2 = PublicKey::from_str(SCAN_PK_2).expect("reading from constant");
        let spend_2 = PublicKey::from_str(SPEND_PK_2).expect("reading from constant");

        let sp_code_1 = SilentPaymentCode::new_v0(scan_1, spend_1, bitcoin::Network::Bitcoin);

        let sp_code_2 = SilentPaymentCode::new_v0(scan_2, spend_2, bitcoin::Network::Bitcoin);

        let sp_code_3 = sp_code_1.add_label(Scalar::MAX).expect("should succeed");

        (partial_secret, vec![sp_code_1, sp_code_2, sp_code_3])
    }

    #[test]
    fn test_create_silentpayment_spk_base() {
        let (partial_secret, sp_codes) = setup_test_data();

        let result =
            create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).expect("should succeed");

        assert_eq!(result.len(), 3);

        for sp_code in &sp_codes {
            assert!(result.contains_key(sp_code));
            assert_eq!(result[sp_code].len(), 1);
        }
    }

    #[test]
    fn test_create_silentpayment_spk_with_empty_outputs() {
        let (partial_secret, _) = setup_test_data();
        let empty_outputs: Vec<SilentPaymentCode> = vec![];

        let result = create_silentpayment_scriptpubkeys(partial_secret, &empty_outputs)
            .expect("should succeed with empty outputs");

        assert!(result.is_empty());
    }

    #[test]
    fn test_create_silentpayment_spk_cache_behavior() {
        let (partial_secret, sp_codes) = setup_test_data();

        assert_eq!(sp_codes[0].scan, sp_codes[2].scan);

        let result =
            create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).expect("should succeed");

        // Get the pubkeys for codes with the same scan key
        let pubkeys_1 = &result[&sp_codes[0]];
        let pubkeys_3 = &result[&sp_codes[2]];

        // They should be different despite having the same scan key
        // because the k value is incremented and the spend keys differ
        assert_ne!(pubkeys_1[0], pubkeys_3[0]);
    }

    #[test]
    fn test_create_silentpayment_spk_multiple_calls_deterministic() {
        let (partial_secret, sp_codes) = setup_test_data();

        // Generate sp_codes twice with the same inputs
        let result_1 =
            create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).expect("should succeed");
        let result_2 =
            create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).expect("should succeed");

        // Results should be identical
        assert_eq!(result_1.len(), result_2.len());

        for sp_code in &sp_codes {
            assert_eq!(result_1[sp_code], result_2[sp_code]);
        }
    }

    #[test]
    fn test_create_silentpayment_spk_duplicate_payment_codes() {
        let (partial_secret, mut sp_codes) = setup_test_data();

        // Add a duplicate of the first code
        sp_codes.push(sp_codes[0].clone());

        let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes)
            .expect("should succeed with duplicates");

        // Should still have only 3 unique entries
        assert_eq!(result.len(), 3);

        // First code should have 2 pubkeys now
        assert_eq!(result[&sp_codes[0]].len(), 2);

        // And the pubkeys should be different due to k incrementing
        let pubkeys = &result[&sp_codes[0]];
        assert_ne!(pubkeys[0], pubkeys[1]);
    }

    #[test]
    fn test_create_silentpayment_spk_large_number_of_sp_codes() {
        let (partial_secret, sp_codes) = setup_test_data();

        let base_code = &sp_codes[0];

        // Create many codes with the same scan key but different spend keys
        let mut sp_codes = Vec::new();
        for _ in 0..100 {
            let label = Scalar::random();

            let code = base_code.add_label(label).expect("should succeed");

            sp_codes.push(code);
        }

        let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes)
            .expect("should succeed with many sp_codes");

        // Should have generated the correct number of sp_codes
        assert_eq!(result.len(), 100);

        // All generated pubkeys should be unique
        let all_pubkeys: Vec<_> = result.values().flat_map(|v| v.iter().cloned()).collect();
        let unique_pubkeys: std::collections::HashSet<_> = all_pubkeys.iter().cloned().collect();
        assert_eq!(all_pubkeys.len(), unique_pubkeys.len());
    }

    #[test]
    fn test_create_silentpayment_spk_different_partial_secrets() {
        let (partial_secret_1, sp_codes) = setup_test_data();
        let partial_secret_2 =
            SecretKey::from_str(PARTIAL_SECRET_2).expect("creating from constant");

        let result_1 = create_silentpayment_scriptpubkeys(partial_secret_1, &sp_codes)
            .expect("should succeed");
        let result_2 = create_silentpayment_scriptpubkeys(partial_secret_2, &sp_codes)
            .expect("should succeed");

        // Results should be different with different partial secrets
        for sp_code in &sp_codes {
            assert_ne!(result_1[sp_code], result_2[sp_code]);
        }
    }
}
