use std::collections::HashMap;

use crate::{
    encoding::SilentPaymentCode,
    receive::extract_pubkey,
    send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, SpSendError},
    LexMin, SpInputs,
};

use bitcoin::{
    key::{Parity, Secp256k1, TweakedPublicKey, Verification},
    psbt::{self, GetKey, KeyRequest},
    secp256k1::{SecretKey, Signing},
    Psbt, ScriptBuf, TapTweakHash, TxIn, TxOut, XOnlyPublicKey,
};

type SpkWithSecret = (ScriptBuf, SecretKey);

struct DataForPartialSecret {
    scripts_with_secrets: Vec<SpkWithSecret>,
    lex_min_outpoint: [u8; 36],
}

impl Default for DataForPartialSecret {
    fn default() -> Self {
        Self {
            scripts_with_secrets: Vec::default(),
            lex_min_outpoint: [0u8; 36],
        }
    }
}

pub fn derive_sp<C, K>(
    psbt: &mut Psbt,
    k: &K,
    recipients: &[SilentPaymentCode],
    secp: &Secp256k1<C>,
) -> Result<Psbt, SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    let DataForPartialSecret {
        scripts_with_secrets,
        lex_min_outpoint,
    } = collect_input_data(psbt, k, secp)?;

    if scripts_with_secrets.is_empty() {
        return Ok(psbt.clone());
    }

    let partial_secret =
        create_silentpayment_partial_secret(&lex_min_outpoint, &scripts_with_secrets)?;
    let silent_payments = create_silentpayment_scriptpubkeys(partial_secret, recipients)?;

    update_outputs(psbt, &silent_payments);

    Ok(psbt.clone())
}

fn collect_input_data<C, K>(
    psbt: &Psbt,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<DataForPartialSecret, SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    let mut data_for_partial_secret = DataForPartialSecret::default();
    let mut lex_min = LexMin::default();

    for (psbt_input, txin) in psbt.inputs.iter().zip(psbt.unsigned_tx.input.iter()) {
        let prevout = get_prevout_script(psbt_input, txin)?;
        let full_txin = build_full_txin(txin, psbt_input)?;

        let sk = extract_pubkey(full_txin, &prevout)
            .map(|(input_type, _pk)| {
                if let SpInputs::P2TR = input_type {
                    get_taproot_secret(psbt_input, k, secp)
                } else {
                    get_non_taproot_secret(psbt_input, k, secp)
                }
            })
            .transpose()?
            .flatten()
            .ok_or(SpSendError::MissingInputsForSharedSecretDerivation)?;

        data_for_partial_secret
            .scripts_with_secrets
            .push((prevout, sk));

        lex_min.update(&txin.previous_output);
    }

    data_for_partial_secret.lex_min_outpoint = lex_min.bytes()?;

    Ok(data_for_partial_secret)
}

fn get_prevout_script(psbt_input: &psbt::Input, txin: &TxIn) -> Result<ScriptBuf, SpSendError> {
    if let Some(txout) = &psbt_input.witness_utxo {
        Ok(txout.script_pubkey.clone())
    } else if let Some(tx) = &psbt_input.non_witness_utxo {
        let txout = tx
            .tx_out(txin.previous_output.vout as usize)
            .map_err(SpSendError::IndexError)?;
        Ok(txout.script_pubkey.clone())
    } else {
        Err(SpSendError::MissingPrevout)
    }
}

fn build_full_txin(txin: &TxIn, psbt_input: &psbt::Input) -> Result<TxIn, SpSendError> {
    if let Some(ref witness) = psbt_input.final_script_witness {
        Ok(TxIn {
            witness: witness.clone(),
            ..txin.clone()
        })
    } else {
        Err(SpSendError::MissingWitness)
    }
}

fn get_taproot_secret<C, K>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    for (&xonly, (_leaf_hashes, key_source)) in psbt_input.tap_key_origins.iter() {
        let internal_privkey =
            if let Ok(Some(privkey)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                privkey
            } else if let Ok(Some(privkey)) = k.get_key(KeyRequest::XOnlyPubkey(xonly), secp) {
                privkey
            } else {
                continue;
            };

        let mut internal_privkey = internal_privkey;
        let (x_only_internal, parity) = internal_privkey.inner.x_only_public_key(secp);

        if let Parity::Odd = parity {
            internal_privkey = internal_privkey.negate();
        }

        let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);

        let external_sk = internal_privkey.inner.add_tweak(&tap_tweak.to_scalar())
            .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function");

        return Ok(Some(external_sk));
    }

    Ok(None)
}

fn get_non_taproot_secret<C, K>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    for (pk, key_source) in psbt_input.bip32_derivation.iter() {
        let privkey =
            if let Ok(Some(privkey)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                privkey
            } else if let Ok(Some(privkey)) =
                k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(*pk)), secp)
            {
                privkey
            } else {
                continue;
            };

        return Ok(Some(privkey.inner));
    }

    Ok(None)
}

fn update_outputs(
    psbt: &mut Psbt,
    silent_payments: &HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>,
) {
    let tx = &psbt.unsigned_tx.clone();

    for (sp_code, x_only_pks) in silent_payments.iter() {
        let placeholder_spk = sp_code.get_placeholder_p2tr_spk();

        for x_only_pubkey in x_only_pks {
            if let Some(idx) = tx
                .output
                .iter()
                .position(|txout| txout.script_pubkey == placeholder_spk)
            {
                let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(*x_only_pubkey);
                let value = tx.output[idx].value;

                psbt.unsigned_tx.output[idx] = TxOut {
                    script_pubkey: ScriptBuf::new_p2tr_tweaked(x_only_tweaked),
                    value,
                };
            }
        }
    }
}
