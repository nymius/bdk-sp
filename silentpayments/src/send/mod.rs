pub mod bip32;
pub mod bip352;
pub mod error;

use crate::{
    compute_shared_secret,
    encoding::SilentPaymentCode,
    hashes::{InputsHash, SharedSecretHash},
    send::error::SpSendError,
};

use bitcoin::{
    hashes::{Hash, HashEngine},
    key::{Secp256k1, TweakedPublicKey},
    secp256k1::{ecdh::shared_secret_point, PublicKey, Scalar, SecretKey},
    ScriptBuf,
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
