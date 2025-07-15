use std::collections::HashMap;

use crate::{
    encoding::SilentPaymentCode,
    send::{
        create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
    },
    LexMin,
};

use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    key::{Parity, Secp256k1},
    secp256k1::SecretKey,
    OutPoint, ScriptBuf, TapTweakHash, XOnlyPublicKey,
};

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

impl XprivSilentPaymentSender {
    pub fn new(xpriv: Xpriv) -> Self {
        Self { xpriv }
    }

    pub fn send_to(
        &self,
        inputs: &[(OutPoint, (ScriptBuf, DerivationPath))],
        outputs: &[SilentPaymentCode],
    ) -> Result<HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>, SpSendError> {
        let secp = Secp256k1::new();

        let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
        let mut lex_min = LexMin::default();
        for (outpoint, (spk, derivation_path)) in inputs.iter() {
            lex_min.update(outpoint);

            let bip32_privkey = self.xpriv.derive_priv(&secp, &derivation_path)?;
            let mut internal_privkey = bip32_privkey.private_key;
            let (x_only_internal, parity) = internal_privkey.x_only_public_key(&secp);

            if let Parity::Odd = parity {
                internal_privkey = internal_privkey.negate();
            }

            let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);

            // NOTE: The parity of the external privkey will be checked on the
            // create_silentpayment_partial_secret function
            let external_privkey = internal_privkey.add_tweak(&tap_tweak.to_scalar())
                .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function");

            spks_with_keys.push((spk.clone(), external_privkey));
        }

        let partial_secret =
            create_silentpayment_partial_secret(&lex_min.bytes()?, &spks_with_keys)?;

        Ok(create_silentpayment_scriptpubkeys(partial_secret, outputs))
    }
}
