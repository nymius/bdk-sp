use bitcoin::{
    key::{Keypair, Secp256k1, Verification},
    psbt::{raw::ProprietaryKey, GetKey, KeyRequest},
    secp256k1::{Message, PublicKey, Scalar, Signing},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    Psbt, TapSighashType, TxOut, XOnlyPublicKey,
};

pub const SPEND_PK_SUBTYPE: u8 = 0x01;

pub fn add_sp_data_to_input(
    psbt: &mut Psbt,
    input_index: usize,
    spend_pk: PublicKey,
    tweak: Scalar,
) {
    let prop_key = ProprietaryKey {
        prefix: b"bip352".to_vec(),
        subtype: self::SPEND_PK_SUBTYPE,
        key: spend_pk.serialize().to_vec(),
    };

    let derivation_data = tweak.to_be_bytes().to_vec();

    // Add to specific input
    if let Some(input) = psbt.inputs.get_mut(input_index) {
        input.proprietary.insert(prop_key, derivation_data);
    }
}

pub fn sign_sp<C, K>(psbt: &mut Psbt, k: &K, secp: &Secp256k1<C>)
where
    C: Signing + Verification,
    K: GetKey,
{
    let tx = psbt.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
    let mut cache = SighashCache::new(&tx);

    for i in 0..psbt.inputs.len() {
        for (key, value) in psbt.inputs[i].proprietary.clone() {
            if key.prefix == b"bip352".to_vec() && key.subtype == self::SPEND_PK_SUBTYPE {
                let spend_pk = PublicKey::from_slice(&key.key).expect("will fix later");
                let mut scalar = [0u8; 32];
                scalar.clone_from_slice(value.as_slice());

                let tweak = Scalar::from_be_bytes(scalar).expect("will fix later");
                let output_key = if let Some(txout) = &psbt.inputs[i].witness_utxo {
                    XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
                        .expect("p2tr script")
                } else {
                    continue;
                };
                let tweaked_spend_pk = spend_pk
                    .add_exp_tweak(secp, &tweak)
                    .expect("will fix later");
                let spend_sk = if let Ok(Some(sk)) =
                    k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(spend_pk)), secp)
                {
                    sk
                } else {
                    continue;
                };
                if psbt.inputs[i].tap_key_sig.is_none()
                    && tweaked_spend_pk.x_only_public_key().0 == output_key
                {
                    let sighash_type = TapSighashType::Default;
                    let prevouts = psbt
                        .inputs
                        .iter()
                        .map(|x| x.witness_utxo.clone().unwrap())
                        .collect::<Vec<TxOut>>();
                    let prevouts = Prevouts::All(&prevouts);

                    let sighash = cache
                        .taproot_key_spend_signature_hash(i, &prevouts, sighash_type)
                        .expect("failed to construct sighash");

                    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
                    let msg = Message::from(sighash);

                    let sk = spend_sk.inner.add_tweak(&tweak).expect("will fix later");
                    let keypair = Keypair::from_secret_key(secp, &sk);

                    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

                    let signature = Signature {
                        signature,
                        sighash_type,
                    };
                    psbt.inputs[i].tap_key_sig = Some(signature);
                }
            }
        }
    }
}
