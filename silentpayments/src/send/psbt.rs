use crate::{
    encoding::SilentPaymentCode,
    receive::extract_pubkey,
    send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys},
    LexMin, SpInputs,
};

use bitcoin::{
    key::{Parity, Secp256k1, TweakedPublicKey, Verification},
    psbt::{GetKey, KeyRequest},
    secp256k1::{SecretKey, Signing},
    Psbt, ScriptBuf, TapTweakHash, TxOut,
};

use super::error::SpSendError;

/// A script pubkey paired with its corresponding secret key for silent payment derivation.
type SpkWithSecret = (ScriptBuf, SecretKey);

/// Contains the data required to create a partial secret for silent payment derivation.
///
/// This structure holds the collected script pubkeys with their associated secret keys and the
/// lexicographically smallest outpoint bytes needed for the silent payment protocol.
#[allow(unused)]
#[derive(Debug)]
struct DataForPartialSecret {
    /// Vector of script pubkeys paired with their corresponding secret keys
    scripts_with_secrets: Vec<SpkWithSecret>,
    /// The lexicographically smallest outpoint as 36 bytes (32 bytes txid + 4 bytes vout)
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
    let tx = psbt.unsigned_tx.clone();

    let mut spks_with_keys: Vec<(ScriptBuf, SecretKey)> = vec![];
    let mut lex_min = LexMin::default();
    for (txin, psbt_input) in tx.input.iter().zip(psbt.inputs.iter()) {
        let prevout = {
            match (&psbt_input.witness_utxo, &psbt_input.non_witness_utxo) {
                (Some(txout), _) => txout.script_pubkey.clone(),
                (_, Some(tx)) => {
                    let txout = tx
                        .tx_out(txin.previous_output.vout as usize)
                        .map_err(SpSendError::IndexError)?;
                    txout.script_pubkey.clone()
                }
                _ => return Err(SpSendError::MissingPrevout),
            }
        };

        lex_min.update(&txin.previous_output);

        let mut full_txin = txin.clone();
        if let Some(ref witness) = psbt_input.final_script_witness {
            full_txin.witness = witness.clone();
        } else {
            return Err(SpSendError::MissingWitness);
        }

        if let Some((input_type, _pk)) = extract_pubkey(full_txin, &prevout) {
            if let SpInputs::P2TR = input_type {
                for (&xonly, (_leaf_hashes, key_source)) in psbt_input.tap_key_origins.iter() {
                    let mut internal_privkey = if let Ok(Some(privkey)) =
                        k.get_key(KeyRequest::Bip32(key_source.clone()), secp)
                    {
                        privkey
                    } else if let Ok(Some(privkey)) =
                        k.get_key(KeyRequest::XOnlyPubkey(xonly), secp)
                    {
                        privkey
                    } else {
                        continue;
                    };
                    let (x_only_internal, parity) = internal_privkey.inner.x_only_public_key(secp);

                    if let Parity::Odd = parity {
                        internal_privkey = internal_privkey.negate();
                    }

                    let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);

                    // NOTE: The parity of the external privkey will be checked on the
                    // create_silentpayment_partial_secret function
                    let external_sk = internal_privkey.inner.add_tweak(&tap_tweak.to_scalar())
                        .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function");

                    spks_with_keys.push((prevout.clone(), external_sk));
                    break;
                }
            } else {
                for (pk, key_source) in psbt_input.bip32_derivation.iter() {
                    let privkey = if let Ok(Some(privkey)) =
                        k.get_key(KeyRequest::Bip32(key_source.clone()), secp)
                    {
                        privkey
                    } else if let Ok(Some(privkey)) =
                        k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(*pk)), secp)
                    {
                        privkey
                    } else {
                        continue;
                    };

                    spks_with_keys.push((prevout.clone(), privkey.inner));
                    break;
                }
            }
        }
    }

    if !spks_with_keys.is_empty() {
        let partial_secret =
            create_silentpayment_partial_secret(&lex_min.bytes()?, &spks_with_keys)?;
        let silent_payments = create_silentpayment_scriptpubkeys(partial_secret, recipients)?;
        for (sp_code, x_only_pks) in silent_payments.iter() {
            let placeholder_spk = sp_code.get_placeholder_p2tr_spk();
            for x_only_pubkey in x_only_pks {
                if let Some(idx) = tx
                    .output
                    .iter()
                    .position(|txout| txout.script_pubkey == placeholder_spk)
                {
                    let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(*x_only_pubkey);
                    let TxOut { value, .. } = tx.output[idx];
                    psbt.unsigned_tx.output[idx] = TxOut {
                        script_pubkey: ScriptBuf::new_p2tr_tweaked(x_only_tweaked),
                        value,
                    };
                }
            }
        }
    }

    Ok(psbt.clone())
}
