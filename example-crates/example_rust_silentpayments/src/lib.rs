use std::collections::{HashMap, HashSet};

use bdk_chain::bitcoin::{
    self,
    bip32::{DerivationPath, Xpriv},
    key::Parity,
    secp256k1::PublicKey,
    NetworkKind, ScriptBuf, Transaction, TxOut,
};
use bitcoin::{
    secp256k1::{self, Scalar, SecretKey},
    Network, OutPoint, XOnlyPublicKey,
};

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

pub struct SilentPaymentAddress {
    pub version: u8,
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub network: Network,
}

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);

    pub(crate) struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub(crate) struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

impl core::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hrp = match self.network {
            Network::Regtest => "sprt",
            Network::Bitcoin => "sp",
            _ => "tsp",
        };

        // let version = bech32::u5::try_from_u8(val.version).unwrap();

        // let B_scan_bytes = val.scan_pubkey.serialize();
        // let B_m_bytes = val.m_pubkey.serialize();

        // let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        // data.insert(0, version);

        // bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
        //
        todo!()
    }
}

impl XprivSilentPaymentSender {
    pub fn new(xpriv: Xpriv) -> Self {
        Self { xpriv }
    }
    pub fn send_to(
        &self,
        inputs: &[(OutPoint, DerivationPath)],
        outputs: Vec<SilentPaymentAddress>,
    ) -> Vec<ScriptBuf> {
        let secp = secp256k1::Secp256k1::new();
        let agg_input_keys = inputs
            .iter()
            .map(|(_op, derivation_path)| {
                let bip32_privkey = self.xpriv.derive_priv(&secp, derivation_path).unwrap();
                let (x_only_internal, parity) = bip32_privkey.private_key.x_only_public_key(&secp);

                let mut internal_privkey = bip32_privkey.private_key;
                if let Parity::Odd = parity {
                    internal_privkey = internal_privkey.negate();
                }

                let tap_tweak =
                    bdk_chain::bitcoin::TapTweakHash::from_key_and_tweak(x_only_internal, None);

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
            .reduce(|acc, sk| acc.add_tweak(&sk.into()).unwrap());

        //         assert!(addr.is_related_to_xonly_pubkey(&x_only_external));

        todo!()
    }
}

pub struct Scanner {
    scan_sk: SecretKey,
    label_lookup: HashMap<PublicKey, (Scalar, u32)>,
}

pub struct SpOutput {
    pub outpoint: OutPoint,
    pub tweak: Scalar,
    pub public_key: XOnlyPublicKey,
    pub label: Option<u32>,
}

impl Scanner {
    pub fn scan_tx(&self, tx: &Transaction, prevouts: &[TxOut]) -> Vec<SpOutput> {
        assert_eq!(tx.input.len(), prevouts.len());

        todo!()
    }
}
