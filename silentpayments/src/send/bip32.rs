use crate::{
    encoding::SilentPaymentCode,
    get_smallest_lexicographic_outpoint,
    send::{
        create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
    },
};

use bitcoin::TapTweakHash;
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    key::{Parity, Secp256k1},
    secp256k1::SecretKey,
    OutPoint, ScriptBuf,
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
    ) -> Result<Vec<ScriptBuf>, SpSendError> {
        let secp = Secp256k1::new();
        let (outpoints, spks_with_derivations): (Vec<_>, Vec<_>) = inputs.iter().cloned().unzip();

        let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
        for (spk, derivation_path) in spks_with_derivations {
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

            spks_with_keys.push((spk, external_privkey));
        }

        let smallest_outpoint_bytes = get_smallest_lexicographic_outpoint(&outpoints);

        let partial_secret =
            create_silentpayment_partial_secret(&smallest_outpoint_bytes, &spks_with_keys)?;

        create_silentpayment_scriptpubkeys(partial_secret, outputs)
    }
}
