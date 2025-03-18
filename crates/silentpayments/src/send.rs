use crate::code::SilentPaymentCode;
use crate::hashes::{InputsHash, SharedSecretHash};
use bitcoin::TapTweakHash;
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    hashes::{Hash, HashEngine},
    key::{Parity, TweakedPublicKey},
    secp256k1::{self, PublicKey, Scalar, SecretKey},
    OutPoint, ScriptBuf,
};
use std::collections::HashMap;

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

impl XprivSilentPaymentSender {
    pub fn new(xpriv: Xpriv) -> Self {
        Self { xpriv }
    }

    // TODO:
    // - [x] Get least outpoint from lexicographic order.
    // - [x] Get a_sum deriving derivations paths for XPriv
    // - [x] Hash them together with A_sum to get input hash.
    // - [x] Group receivers by B_scan, and subgroup them by B_spend. NOTE: sort of (look caches)
    // - [x] Multiply the B_scan from each group with the input hash, to get the shared secret.
    // - [x] For each B_spend subgroup, concatenate the shared secret to the subgroup order and get
    // the final B_spend tweak, t_k. Later compute `T_k = t_k . G`
    // - [x] Get final script pubkey by computing P_mn = B_m + T_k
    // - [x] Encode P_mn as a tarpoot script pubkey
    // - [x] Match the taproot script pubkey with the desired amount to send to it
    pub fn send_to(
        &self,
        inputs: &[(OutPoint, DerivationPath)],
        outputs: &[SilentPaymentCode],
    ) -> Vec<ScriptBuf> {
        let secp = secp256k1::Secp256k1::new();
        let (outpoints, derivation_paths): (Vec<_>, Vec<_>) = inputs.iter().cloned().unzip();
        let smallest_outpoint = outpoints
            .into_iter()
            .map(|x| {
                let mut outpoint_bytes = [0u8; 36];
                outpoint_bytes[..32].copy_from_slice(x.txid.to_raw_hash().as_byte_array());
                outpoint_bytes[32..36].copy_from_slice(&x.vout.to_le_bytes());
                outpoint_bytes
            })
            .min()
            .unwrap();
        let a_sum = derivation_paths
            .iter()
            .map(|derivation_path| {
                let bip32_privkey = self.xpriv.derive_priv(&secp, derivation_path).unwrap();
                let (x_only_internal, parity) = bip32_privkey.private_key.x_only_public_key(&secp);

                let mut internal_privkey = bip32_privkey.private_key;
                if let Parity::Odd = parity {
                    internal_privkey = internal_privkey.negate();
                }

                let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);

                let (_x_only_external, parity) = x_only_internal
                    .add_tweak(&secp, &tap_tweak.to_scalar())
                    .unwrap();

                let mut external_privkey =
                    internal_privkey.add_tweak(&tap_tweak.to_scalar()).unwrap();

                if let Parity::Odd = parity {
                    external_privkey = external_privkey.negate();
                }

                external_privkey
            })
            .reduce(|acc, sk| acc.add_tweak(&sk.into()).unwrap())
            .unwrap();

        #[allow(non_snake_case)]
        let A_sum = a_sum.public_key(&secp);

        let input_hash = {
            let mut eng = InputsHash::engine();
            eng.input(&smallest_outpoint);
            eng.input(&A_sum.serialize());
            let hash = InputsHash::from_engine(eng);
            Scalar::from_be_bytes(hash.to_byte_array())
                .expect("hash value greater than curve order")
        };

        // Cache to avoid recomputing ecdh shared secret for each B_scan
        let mut ecdh_shared_secret_cache = <HashMap<PublicKey, PublicKey>>::new();

        #[allow(non_snake_case)]
        // Cache to know the amount of B_m already added to the account
        let B_m_count_cache = <HashMap<PublicKey, u32>>::new();

        outputs
            .iter()
            .map(|SilentPaymentCode { scan, spend, .. }| {
                let shared_secret =
                    if let Some(ecdh_shared_secret) = ecdh_shared_secret_cache.get(scan) {
                        *ecdh_shared_secret
                    } else {
                        // NOTE: Should we optimize here using secp256k1::ecdh::shared_secret_point?
                        // ANSWER: No, shared_secret_point is to get a Secret Key instead of public
                        // one
                        let partial_secret = Scalar::from(a_sum.mul_tweak(&input_hash).unwrap());
                        let ecdh_shared_secret = scan.mul_tweak(&secp, &partial_secret).unwrap();
                        ecdh_shared_secret_cache.insert(*scan, ecdh_shared_secret);
                        ecdh_shared_secret
                    };

                let k = if let Some(count) = B_m_count_cache.get(spend) {
                    count + 1
                } else {
                    0
                };

                #[allow(non_snake_case)]
                let T_k = {
                    let mut eng = SharedSecretHash::engine();
                    eng.input(&shared_secret.serialize());
                    eng.input(&k.to_le_bytes());
                    let hash = SharedSecretHash::from_engine(eng);
                    let t_k = SecretKey::from_slice(&hash.to_byte_array()).unwrap();
                    t_k.public_key(&secp)
                };

                #[allow(non_snake_case)]
                let P_mn = spend.combine(&T_k).unwrap();
                // NOTE: Should we care about parity here? Ask @LLFourn
                let (x_only_pubkey, _) = P_mn.x_only_public_key();
                let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

                // NOTE: Creating the TxOut here is too much?
                // NOTE: Is better to produce a script pubkey and return a match to the address?
                // Does that matter after creating the TxOuts?
                // NOTE: We need a way to match roughly the silent payment address with the amount
                // we wanted to send to them.
                ScriptBuf::new_p2tr_tweaked(x_only_tweaked)
            })
            .collect::<Vec<ScriptBuf>>()
    }
}
