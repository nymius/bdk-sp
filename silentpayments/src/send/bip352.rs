use crate::send::create_silentpayment_scriptpubkeys;
use crate::{
    encoding::SilentPaymentCode,
    receive::SpOut,
    send::{
        create_silentpayment_partial_secret, error::SpSendError,
        get_smallest_lexicographic_outpoint,
    },
};
use bitcoin::{
    key::{Parity, Secp256k1, TweakedPublicKey},
    secp256k1::{Scalar, SecretKey},
    OutPoint, ScriptBuf,
};

pub struct SpSender {
    spend_sk: SecretKey,
}

impl SpSender {
    pub fn new(spend_sk: SecretKey) -> Self {
        Self { spend_sk }
    }

    pub fn send_to(
        &self,
        inputs: &[SpOut],
        outputs: &[SilentPaymentCode],
    ) -> Result<Vec<ScriptBuf>, SpSendError> {
        let secp = Secp256k1::new();

        let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
        let mut outpoints = <Vec<OutPoint>>::new();
        for spout in inputs {
            let mut spout_sk = self.spend_sk.add_tweak(&Scalar::from(spout.tweak))?;
            let (x_only_external, parity) = spout_sk.x_only_public_key(&secp);

            if let Parity::Odd = parity {
                spout_sk = spout_sk.negate();
            }

            let tweaked_pk = TweakedPublicKey::dangerous_assume_tweaked(x_only_external);
            let spk = ScriptBuf::new_p2tr_tweaked(tweaked_pk);

            let sp_data = (spk, spout_sk);
            spks_with_keys.push(sp_data);
            outpoints.push(spout.outpoint);
        }

        let smallest_outpoint_bytes = get_smallest_lexicographic_outpoint(&outpoints);

        let partial_secret =
            create_silentpayment_partial_secret(&smallest_outpoint_bytes, &spks_with_keys)?;

        create_silentpayment_scriptpubkeys(partial_secret, outputs)
    }
}
