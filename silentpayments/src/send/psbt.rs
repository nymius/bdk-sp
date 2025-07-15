use super::{
    create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
};
use crate::{encoding::SilentPaymentCode, receive::extract_pubkey, LexMin, SpInputs};
use bitcoin::{
    bip32::KeySource,
    key::{Parity, Secp256k1, TweakedPublicKey, Verification},
    psbt::{self, GetKey, KeyRequest},
    secp256k1::{SecretKey, Signing},
    PrivateKey, Psbt, ScriptBuf, TapLeafHash, TapTweakHash, TxIn, TxOut, XOnlyPublicKey,
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
};

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
        let silent_payments = create_silentpayment_scriptpubkeys(partial_secret, recipients);
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

/// Collects input data required for silent payment derivation from a [`Psbt`].
///
/// This function iterates through all [`Psbt`] inputs, request private keys where available,
/// and determines the lexicographically smallest outpoint for the silent payment protocol.
///
/// # Arguments
///
/// * `psbt` - The [`Psbt`] to process
/// * `k` - A key provider implementing the [`GetKey`] trait
/// * `secp` - A [`Secp256k1`] context for cryptographic operations
///
/// # Returns
///
/// Returns [`DataForPartialSecret`] containing the collected script pubkeys with secrets
/// and the lexicographically smallest outpoint, or a [`SpSendError`] if no usable inputs
/// are found.
#[allow(unused)]
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

        let maybe_secret_key = extract_pubkey(full_txin.clone(), &prevout)
            .map(|pubkey_data| match pubkey_data {
                (SpInputs::P2TR, even_tr_output_key) => {
                    match get_taproot_secret(psbt_input, k, secp) {
                        Ok(Some(secret)) => {
                            let (xonly, _) = secret.x_only_public_key(secp);
                            if even_tr_output_key == xonly.public_key(Parity::Even) {
                                Ok(Some(secret))
                            } else {
                                Err(SpSendError::KeyError)
                            }
                        }
                        Ok(None) => Ok(None),
                        Err(_) => Err(SpSendError::KeyError),
                    }
                }
                _ => get_non_taproot_secret(psbt_input, k, secp).map_err(|_| SpSendError::KeyError),
            })
            .transpose()?
            .flatten();

        if let Some(secret_key) = maybe_secret_key {
            data_for_partial_secret
                .scripts_with_secrets
                .push((prevout, secret_key));
        }

        lex_min.update(&txin.previous_output);
    }

    if data_for_partial_secret.scripts_with_secrets.is_empty() {
        Err(SpSendError::MissingInputsForSharedSecretDerivation)
    } else {
        data_for_partial_secret.lex_min_outpoint = lex_min
            .bytes()
            .expect("should not fail as scripts_with_secrets is non empty and this is a stronger precondition");

        Ok(data_for_partial_secret)
    }
}

/// Extracts the previous output script from a [`Psbt`] input.
///
/// This function attempts to retrieve the script pubkey from either the witness UTXO
/// or the non-witness UTXO, depending on what's available in the [`Psbt`] input.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input to extract the script from
/// * `txin` - The corresponding transaction input
///
/// # Returns
///
/// Returns the script pubkey of the previous output, or a [`SpSendError`] if neither
/// witness nor non-witness UTXO is available, or if the output index is invalid.
#[allow(unused)]
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

/// Builds a complete transaction input with witness or script_sig data from [`Psbt`] input.
///
/// This function constructs a complete [`TxIn`] by copying the base transaction input and adding
/// the final witness or script_sig from the [`Psbt`] input data. For this step to succeed is
/// important the [`Psbt`] is finalized.
///
/// # Arguments
///
/// * `txin` - The base transaction input
/// * `psbt_input` - The [`Psbt`] input containing witness or script_sig data
///
/// # Returns
///
/// Returns a complete [`TxIn`] with witness or script_sig populated, or a [`SpSendError`] if
/// neither final witness nor script_sig is available.
#[allow(unused)]
fn build_full_txin(txin: &TxIn, psbt_input: &psbt::Input) -> Result<TxIn, SpSendError> {
    if let Some(ref witness) = psbt_input.final_script_witness {
        Ok(TxIn {
            witness: witness.clone(),
            ..txin.clone()
        })
    } else if let Some(ref script_sig) = psbt_input.final_script_sig {
        Ok(TxIn {
            script_sig: script_sig.clone(),
            ..txin.clone()
        })
    } else {
        Err(SpSendError::MissingWitness)
    }
}

/// Retrieves the secret key for a taproot input from [`Psbt`] data.
///
/// This function attempts to derive the secret key for a taproot input by trying
/// both BIP32 derivation and x-only public key lookup. It handles the taproot-specific
/// key tweaking and parity adjustment required for proper key derivation.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input containing taproot key origin data
/// * `k` - A key provider implementing the `GetKey` trait
/// * `secp` - A secp256k1 context for cryptographic operations
///
/// # Returns
///
/// Returns `Some(SecretKey)` if a valid taproot secret key is found, `None` if no
/// key can be derived, or a [`GetKey`] error if all key retrieval fail.
#[allow(unused)]
fn get_taproot_secret<C, K, E>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    let get_taproot_output_key = |internal_privkey: PrivateKey| -> SecretKey {
        let mut internal_privkey = internal_privkey;
        let (x_only_internal, parity) = internal_privkey.inner.x_only_public_key(secp);

        if let Parity::Odd = parity {
            internal_privkey = internal_privkey.negate();
        }

        let tap_tweak =
            TapTweakHash::from_key_and_tweak(x_only_internal, psbt_input.tap_merkle_root);

        internal_privkey.inner.add_tweak(&tap_tweak.to_scalar())
        .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function")
    };

    let try_tr_keys = |(xonly, (_leaves, key_source)): (
        &XOnlyPublicKey,
        &(Vec<TapLeafHash>, KeySource),
    )|
     -> Result<Option<PrivateKey>, E> {
        match k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
            Ok(Some(privkey)) => Ok(Some(privkey)),
            Ok(None) | Err(..) => k.get_key(KeyRequest::XOnlyPubkey(*xonly), secp),
        }
    };

    psbt_input
        .tap_key_origins
        .iter()
        .find_map(|key_origin| match try_tr_keys(key_origin) {
            Ok(Some(private_key)) => Some(Ok(get_taproot_output_key(private_key))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .transpose()
}

/// Retrieves the secret key for a non-taproot input from [`Psbt`] data.
///
/// This function attempts to derive the secret key for non-taproot inputs by trying both BIP32
/// derivation and public key lookup.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input containing BIP32 derivation data
/// * `k` - A key provider implementing the [`GetKey`] trait
/// * `secp` - A [`Secp256k1`] context for cryptographic operations
///
/// # Returns
///
/// Returns `Some(SecretKey)` if a valid non-taproot secret key is found, `None` if no
/// key can be derived, or a [`GetKey`] error if all key retrieval fail.
#[allow(unused)]
fn get_non_taproot_secret<C, K, E>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    let try_keys = |(pk, key_source): (&bitcoin::secp256k1::PublicKey, &KeySource)| -> Result<Option<PrivateKey>, E> {
        match k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
            Ok(Some(privkey)) => Ok(Some(privkey)),
            Ok(None) | Err(..) => k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(*pk)), secp)
        }
    };

    psbt_input
        .bip32_derivation
        .iter()
        .find_map(|key_origin| match try_keys(key_origin) {
            Ok(Some(private_key)) => Some(Ok(private_key.inner)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .transpose()
}

/// Updates [`Psbt`] outputs with derived silent payment script pubkeys.
///
/// This function replaces placeholder script pubkeys in the [`Psbt`] outputs with the actual
/// silent payment script pubkeys derived from the input processing. It validates that
/// the number of derivations matches the number of placeholder outputs for each
/// silent payment code.
///
/// # Arguments
///
/// * `psbt` - A mutable reference to the [`Psbt`] whose outputs will be updated
/// * `silent_payments` - A mapping of silent payment codes to their derived public keys
///
/// # Returns
///
/// Returns `Ok(())` on successful update, or a [`SpSendError`] if there's a mismatch
/// between the number of derivations and outputs.
///
/// # Errors
///
/// * [`SpSendError::MissingDerivations`] - More placeholder outputs than derivations
/// * [`SpSendError::MissingOutputs`] - More derivations than placeholder outputs
#[allow(unused)]
fn update_outputs(
    psbt: &mut Psbt,
    silent_payments: &HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>,
) -> Result<(), SpSendError> {
    let placeholder_spk_to_idx = {
        let mut map = <BTreeMap<ScriptBuf, Vec<usize>>>::new();
        for (idx, txout) in psbt.unsigned_tx.output.iter().enumerate() {
            map.entry(txout.script_pubkey.clone())
                .or_default()
                .push(idx);
        }
        map
    };

    for (sp_code, x_only_pks) in silent_payments.iter() {
        let placeholder_spk = sp_code.get_placeholder_p2tr_spk();

        if let Some(indexes) = placeholder_spk_to_idx.get(&placeholder_spk) {
            match indexes.len().cmp(&x_only_pks.len()) {
                Ordering::Greater => return Err(SpSendError::MissingDerivations),
                Ordering::Less => return Err(SpSendError::MissingOutputs),
                Ordering::Equal => {
                    for (idx, xonly_pk) in indexes.iter().zip(x_only_pks) {
                        let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(*xonly_pk);
                        let value = psbt.unsigned_tx.output[*idx].value;

                        psbt.unsigned_tx.output[*idx] = TxOut {
                            script_pubkey: ScriptBuf::new_p2tr_tweaked(x_only_tweaked),
                            value,
                        };
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{
        encoding::SilentPaymentCode,
        send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys},
        LexMin,
    };
    use bitcoin::{
        ecdsa,
        hashes::Hash,
        key::{Keypair, Secp256k1},
        secp256k1::{Message, PublicKey, Scalar, SecretKey},
        taproot,
        transaction::Version,
        Amount, EcdsaSighashType, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence, TapSighashType,
        Transaction, TxIn, TxOut, WPubkeyHash, Witness, XOnlyPublicKey,
    };
    use std::{collections::HashMap, str::FromStr};

    const SCAN_PK_1: &str = "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b";
    const SPEND_PK_1: &str = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
    const SCAN_PK_2: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const SPEND_PK_2: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const PRIV_KEY: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";

    fn setup_sp_codes() -> Vec<SilentPaymentCode> {
        let scan_1 = PublicKey::from_str(SCAN_PK_1).expect("reading from constant");
        let spend_1 = PublicKey::from_str(SPEND_PK_1).expect("reading from constant");

        let scan_2 = PublicKey::from_str(SCAN_PK_2).expect("reading from constant");
        let spend_2 = PublicKey::from_str(SPEND_PK_2).expect("reading from constant");

        let sp_code_1 = SilentPaymentCode::new_v0(scan_1, spend_1, bitcoin::Network::Bitcoin);

        let sp_code_2 = SilentPaymentCode::new_v0(scan_2, spend_2, bitcoin::Network::Bitcoin);

        let sp_code_3 = sp_code_1.add_label(Scalar::MAX).expect("should succeed");

        vec![sp_code_1, sp_code_2, sp_code_3]
    }

    fn get_placeholder_txout(value: u64, sp_code: &SilentPaymentCode) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: sp_code.get_placeholder_p2tr_spk(),
        }
    }

    fn create_p2tr_input_data() -> (PrivateKey, XOnlyPublicKey, ScriptBuf, Witness) {
        let secp = Secp256k1::new();
        let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
        let witness = {
            let message = Message::from_digest([1u8; 32]);
            let keypair = Keypair::from_secret_key(&secp, &prv_k.inner);
            let signature = secp.sign_schnorr(&message, &keypair);
            let tr_sig = taproot::Signature {
                signature,
                sighash_type: TapSighashType::All,
            };
            Witness::p2tr_key_spend(&tr_sig)
        };
        let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);
        let p2tr_spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
        (prv_k, xonly_pubkey, p2tr_spk, witness)
    }

    fn create_non_p2tr_input_data() -> (PrivateKey, PublicKey, ScriptBuf, Witness) {
        let secp = Secp256k1::new();
        let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
        let pubkey = prv_k.public_key(&secp);
        let witness = {
            let message = Message::from_digest([1u8; 32]);
            let signature = secp.sign_ecdsa(&message, &prv_k.inner);
            let ecdsa_sig = ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            };
            Witness::p2wpkh(&ecdsa_sig, &pubkey.inner)
        };
        let wpk_hash = WPubkeyHash::hash(&pubkey.inner.serialize());
        let p2wpkh_spk = ScriptBuf::new_p2wpkh(&wpk_hash);
        (prv_k, pubkey.inner, p2wpkh_spk, witness)
    }

    fn create_test_psbt(outputs: Vec<TxOut>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn get_sp_derivations(
        psbt: &Psbt,
        spk_with_key: &[(ScriptBuf, SecretKey)],
        sp_codes: &[SilentPaymentCode],
    ) -> HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>> {
        let mut lex_min = LexMin::default();
        lex_min.update(&psbt.unsigned_tx.input[0].previous_output);

        let partial_secret = create_silentpayment_partial_secret(
            &lex_min.bytes().expect("should succeed"),
            spk_with_key,
        )
        .expect("should succeed");

        create_silentpayment_scriptpubkeys(partial_secret, sp_codes)
    }

    mod collect_input_data {
        use super::{
            create_non_p2tr_input_data, create_p2tr_input_data, create_test_psbt,
            get_placeholder_txout,
            key_provider_mock::{create_key_source, MockKeyProvider},
            setup_sp_codes,
        };
        use crate::{
            encoding::SilentPaymentCode,
            send::{error::SpSendError, psbt::collect_input_data},
        };
        use bitcoin::{
            bip32::{DerivationPath, Fingerprint},
            consensus::Decodable,
            hex::test_hex_unwrap as hex,
            key::Secp256k1,
            psbt::KeyRequest,
            Amount, PrivateKey, Psbt, ScriptBuf, TapNodeHash, Transaction, TxOut, Witness,
            XOnlyPublicKey,
        };
        use std::{collections::BTreeMap, str::FromStr};

        #[test]
        fn success_p2tr() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
            let key_source = create_key_source();
            psbt.inputs[0]
                .tap_key_origins
                .insert(xonly_pk, (vec![], key_source.clone()));
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey,
            });
            psbt.inputs[0].final_script_witness = Some(witness);

            let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(result.is_ok());
            let data = result.unwrap();
            assert_eq!(data.scripts_with_secrets.len(), 1);
            assert!(!data.lex_min_outpoint.is_empty());
        }

        #[test]
        fn success_non_p2tr() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            let (priv_key, pubkey, script_pubkey, witness) = create_non_p2tr_input_data();
            let key_source = create_key_source();
            psbt.inputs[0]
                .bip32_derivation
                .insert(pubkey, key_source.clone());
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey,
            });
            psbt.inputs[0].final_script_witness = Some(witness);
            let key_provider = MockKeyProvider::default().with_public_key(pubkey, priv_key);
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(result.is_ok());
            let data = result.unwrap();
            assert_eq!(data.scripts_with_secrets.len(), 1);
            assert!(!data.lex_min_outpoint.is_empty());
        }

        #[test]
        fn success_p2tr_script_path_spend() {
            let secp = Secp256k1::new();
            let sp_code = SilentPaymentCode::try_from("tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt").expect("should succeed");
            let mut unsigned_tx: Transaction = Decodable::consensus_decode(&mut hex!("0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967").as_slice()).unwrap();
            unsigned_tx.output[0].script_pubkey = sp_code.get_placeholder_p2tr_spk();

            let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("should succeed");

            let prv_k =
                PrivateKey::from_str("cP6qHcnCn3SFDXdDun4uo5f3X19KyshUuchdbBpaZfB2nG7vYuJN")
                    .expect("reading from constant");

            let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);

            let key_source = (
                Fingerprint::from_str("b8532cd3").unwrap(),
                DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
            );
            psbt.inputs[0]
                .tap_key_origins
                .insert(xonly_pubkey, (vec![], key_source.clone()));
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::from_hex(
                    "512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d",
                )
                .expect("should suceed"),
            });
            psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[hex!("0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa6185740a5da084901627205e860d6530ff5ff580fc3841b779ad8535ffd7b466664aa0280c218aa05a1054c73b1f717b6c5badf70e71e5091b4b34e25ec3584243fd0604032a0bad48af9b3263d331ba2c789a931af81755c67dfefab28f8e40658545e6659eeb93d2c501ac79914ca82f4dbdcd669d34c7de73b4c243400926cffeb42b640015f5b58eb820676382521bb38b9d0c16d40c6a1b710242232d3d8276145aee859667d3caf9b72acecbfa3be33ce7afb9bda70b19451c58550bb1076125463c240ba0ba063d92ef71a35a1bdbd41b165d71825d6b5d9555781a3a6c35aba5864c82c4e53a7656458dc8bd586a6de749b6ab59cbb5ec4e2264a185ef7b79db3ea9c408176c65f6486f5c9a7d466fe86dfed7d55f8fc480b5843414696842f1efc689e74fce36a0b318535ef86864d8f83ac4bb60085c2b45c0547b9657def51b52b8e40b5f95b03c77b685314848a292d05bf350cdad506bcb2601b634779e956235aef3bade98a812f046d47060fbf9965ac0ef016e6ef09540c1c7d5b2fe447192cbd405ea9e1a58685ef958db8aa529d3fbfcc1182e252a35715bf9b2c35a30c73e718a65e8a8c0141eaac72af71a1dd7f19c53aaead75ae5b963a4eee5d1228c389844094a38c8574e6089c33d2c37d6f889adb671ef09a188e91cf032e97a3e25e9636901096e1cc92d17fbf4c581e5a1915de53f807f3198f4a2b829fc3a4479f6bb54017e68b70fd9e5c94c6f99abf284f5da42365a2e5fd4f0971bf5cb68aea3408c0d05ace043c15e70958c73f7455db3a22e3e5fb0240749a9dc52aa66a554fb06b40c478230871c12b60bc7cae151e411aa779780a8e6a7afd57aa763185809259fc7853f65e712d1ef178d4750f66e1b6db3cae7efcec5308b815b39fe8498f404afd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b141c1259b7a61aa66c551a6cd35ccc35e9e011ecbbddbbb673acba71e2e4cc11e8883326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f6")]));

            psbt.inputs[0].tap_merkle_root = Some(
                TapNodeHash::from_str(
                    "ed68ae7481bbbc9afbcae463308302c41f3efdb3ad73c608b6e4424146f0a9af",
                )
                .expect("should succeed"),
            );
            let mut key_provider: BTreeMap<XOnlyPublicKey, PrivateKey>;
            key_provider = BTreeMap::new();
            key_provider.insert(xonly_pubkey, prv_k);

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(result.is_ok());
        }

        #[test]
        fn missing_merkle_root_for_p2tr_script_path_spend() {
            let secp = Secp256k1::new();
            let sp_code = SilentPaymentCode::try_from("tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt").expect("should succeed");
            let mut unsigned_tx: Transaction = Decodable::consensus_decode(&mut hex!("0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967").as_slice()).unwrap();
            unsigned_tx.output[0].script_pubkey = sp_code.get_placeholder_p2tr_spk();

            let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("should succeed");

            let prv_k =
                PrivateKey::from_str("cP6qHcnCn3SFDXdDun4uo5f3X19KyshUuchdbBpaZfB2nG7vYuJN")
                    .expect("reading from constant");

            let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);

            let key_source = (
                Fingerprint::from_str("b8532cd3").unwrap(),
                DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
            );
            psbt.inputs[0]
                .tap_key_origins
                .insert(xonly_pubkey, (vec![], key_source.clone()));
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::from_hex(
                    "512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d",
                )
                .expect("should suceed"),
            });
            psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[hex!("0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa6185740a5da084901627205e860d6530ff5ff580fc3841b779ad8535ffd7b466664aa0280c218aa05a1054c73b1f717b6c5badf70e71e5091b4b34e25ec3584243fd0604032a0bad48af9b3263d331ba2c789a931af81755c67dfefab28f8e40658545e6659eeb93d2c501ac79914ca82f4dbdcd669d34c7de73b4c243400926cffeb42b640015f5b58eb820676382521bb38b9d0c16d40c6a1b710242232d3d8276145aee859667d3caf9b72acecbfa3be33ce7afb9bda70b19451c58550bb1076125463c240ba0ba063d92ef71a35a1bdbd41b165d71825d6b5d9555781a3a6c35aba5864c82c4e53a7656458dc8bd586a6de749b6ab59cbb5ec4e2264a185ef7b79db3ea9c408176c65f6486f5c9a7d466fe86dfed7d55f8fc480b5843414696842f1efc689e74fce36a0b318535ef86864d8f83ac4bb60085c2b45c0547b9657def51b52b8e40b5f95b03c77b685314848a292d05bf350cdad506bcb2601b634779e956235aef3bade98a812f046d47060fbf9965ac0ef016e6ef09540c1c7d5b2fe447192cbd405ea9e1a58685ef958db8aa529d3fbfcc1182e252a35715bf9b2c35a30c73e718a65e8a8c0141eaac72af71a1dd7f19c53aaead75ae5b963a4eee5d1228c389844094a38c8574e6089c33d2c37d6f889adb671ef09a188e91cf032e97a3e25e9636901096e1cc92d17fbf4c581e5a1915de53f807f3198f4a2b829fc3a4479f6bb54017e68b70fd9e5c94c6f99abf284f5da42365a2e5fd4f0971bf5cb68aea3408c0d05ace043c15e70958c73f7455db3a22e3e5fb0240749a9dc52aa66a554fb06b40c478230871c12b60bc7cae151e411aa779780a8e6a7afd57aa763185809259fc7853f65e712d1ef178d4750f66e1b6db3cae7efcec5308b815b39fe8498f404afd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b141c1259b7a61aa66c551a6cd35ccc35e9e011ecbbddbbb673acba71e2e4cc11e8883326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f6")]));

            let mut key_provider: BTreeMap<XOnlyPublicKey, PrivateKey>;
            key_provider = BTreeMap::new();
            key_provider.insert(xonly_pubkey, prv_k);

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
        }

        #[test]
        fn key_error() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            let (_, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
            let key_source = create_key_source();
            psbt.inputs[0]
                .tap_key_origins
                .insert(xonly_pk, (vec![], key_source.clone()));
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey,
            });
            psbt.inputs[0].final_script_witness = Some(witness);

            let key_provider =
                MockKeyProvider::default().with_error(KeyRequest::XOnlyPubkey(xonly_pk));
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
        }

        #[test]
        fn missing_key() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            let (_, _, script_pubkey, witness) = create_p2tr_input_data();
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey,
            });
            psbt.inputs[0].final_script_witness = Some(witness);
            let key_provider = MockKeyProvider::default();
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(matches!(
                result.unwrap_err(),
                SpSendError::MissingInputsForSharedSecretDerivation
            ));
        }

        #[test]
        fn get_prevout_error() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            psbt.inputs[0].final_script_witness = Some(Witness::new());
            let key_provider = MockKeyProvider::default();
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SpSendError::MissingPrevout));
        }

        #[test]
        fn build_full_txin_error() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];
            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());
            let (_, _, script_pubkey, _) = create_p2tr_input_data();
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey,
            });
            psbt.inputs[0].final_script_witness = None;
            let key_provider = MockKeyProvider::default();
            let secp = Secp256k1::new();

            let result = collect_input_data(&psbt, &key_provider, &secp);

            assert!(result.is_err());
        }
    }

    mod get_prevout_script {
        use crate::send::{psbt::get_prevout_script, SpSendError};
        use bitcoin::{hashes::Hash, psbt, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

        #[test]
        fn with_witness_utxo() {
            let script = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
                .expect("should succeed");
            let witness_utxo = TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script.clone(),
            };

            let psbt_input = psbt::Input {
                witness_utxo: Some(witness_utxo),
                non_witness_utxo: None,
                ..Default::default()
            };

            let txin = TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let result = get_prevout_script(&psbt_input, &txin);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), script);
        }

        #[test]
        fn with_non_witness_utxo_valid_index() {
            ScriptBuf::from_hex("76a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac")
                .expect("should succeed");
            let script = ScriptBuf::new();
            let txout = TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: script.clone(),
            };

            let non_witness_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![txout],
            };

            let psbt_input = psbt::Input {
                witness_utxo: None,
                non_witness_utxo: Some(non_witness_tx),
                ..Default::default()
            };

            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let result = get_prevout_script(&psbt_input, &txin);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), script);
        }

        #[test]
        fn with_non_witness_utxo_invalid_index() {
            let txout = TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: ScriptBuf::new(),
            };

            let non_witness_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![txout],
            };

            let psbt_input = psbt::Input {
                witness_utxo: None,
                non_witness_utxo: Some(non_witness_tx),
                ..Default::default()
            };

            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let result = get_prevout_script(&psbt_input, &txin);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SpSendError::IndexError(_)));
        }

        #[test]
        fn missing_prevout() {
            let psbt_input = psbt::Input {
                witness_utxo: None,
                non_witness_utxo: None,
                ..Default::default()
            };

            let txin = TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let result = get_prevout_script(&psbt_input, &txin);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SpSendError::MissingPrevout));
        }

        #[test]
        fn witness_takes_precedence_over_non_witness() {
            let witness_script =
                ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
                    .expect("should succeed");

            let witness_utxo = TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: witness_script.clone(),
            };

            let non_witness_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![witness_utxo.clone()],
            };

            let psbt_input = psbt::Input {
                witness_utxo: Some(witness_utxo),
                non_witness_utxo: Some(non_witness_tx),
                ..Default::default()
            };

            let txin = TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let result = get_prevout_script(&psbt_input, &txin);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), witness_script);
        }
    }

    mod build_full_txin {
        use crate::send::{error::SpSendError, psbt::build_full_txin};
        use bitcoin::{hashes::Hash, psbt, OutPoint, ScriptBuf, Sequence, TxIn, Txid, Witness};

        fn create_txin() -> TxIn {
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[0u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }
        }

        #[test]
        fn witness_present() {
            let txin = create_txin();
            let mut witness = Witness::new();
            witness.push(vec![0x01, 0x02, 0x03]);

            let psbt_input = psbt::Input {
                final_script_witness: Some(witness.clone()),
                ..Default::default()
            };

            let result = build_full_txin(&txin, &psbt_input);

            assert!(result.is_ok());
            let full_txin = result.unwrap();
            assert_eq!(full_txin.witness, witness);
        }

        #[test]
        fn script_sig_and_witness_present() {
            let txin = create_txin();
            let mut witness = Witness::new();
            witness.push(vec![0x01, 0x02, 0x03]);

            let psbt_input = psbt::Input {
                final_script_witness: Some(witness.clone()),
                final_script_sig: Some(ScriptBuf::new()),
                ..Default::default()
            };

            let result = build_full_txin(&txin, &psbt_input);

            assert!(result.is_ok());
            let full_txin = result.unwrap();
            assert_eq!(full_txin.witness, witness);
        }

        #[test]
        fn script_sig_present_witness_is_none() {
            let txin = create_txin();

            let psbt_input = psbt::Input {
                final_script_sig: Some(ScriptBuf::new()),
                ..Default::default()
            };

            let result = build_full_txin(&txin, &psbt_input);

            assert!(result.is_ok());
            let full_txin = result.unwrap();
            assert_eq!(full_txin.script_sig, ScriptBuf::new());
        }

        #[test]
        fn witness_is_none_and_script_sig_is_none() {
            let txin = create_txin();
            let psbt_input = psbt::Input {
                ..Default::default()
            };

            let result = build_full_txin(&txin, &psbt_input);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SpSendError::MissingWitness));
        }
    }

    mod key_provider_mock {
        use bitcoin::{
            bip32::{DerivationPath, Fingerprint, KeySource},
            psbt::{GetKey, KeyRequest},
            secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, XOnlyPublicKey},
            PrivateKey,
        };
        use std::{collections::BTreeMap, str::FromStr};

        #[derive(Default)]
        pub struct MockKeyProvider {
            bip32_keys: BTreeMap<KeySource, PrivateKey>,
            xonly_keys: BTreeMap<XOnlyPublicKey, PrivateKey>,
            public_keys: BTreeMap<PublicKey, PrivateKey>,
            should_error: Option<KeyRequest>,
        }

        #[derive(Debug, PartialEq)]
        pub struct TestError;

        impl MockKeyProvider {
            pub fn with_bip32_key(
                mut self,
                key_source: KeySource,
                private_key: PrivateKey,
            ) -> Self {
                self.bip32_keys.insert(key_source, private_key);
                self
            }

            pub fn with_xonly_key(
                mut self,
                xonly: XOnlyPublicKey,
                private_key: PrivateKey,
            ) -> Self {
                self.xonly_keys.insert(xonly, private_key);
                self
            }

            pub fn with_public_key(mut self, pubkey: PublicKey, private_key: PrivateKey) -> Self {
                self.public_keys.insert(pubkey, private_key);
                self
            }

            pub fn with_error(mut self, key_request: KeyRequest) -> Self {
                self.should_error = Some(key_request);
                self
            }
        }

        impl GetKey for MockKeyProvider {
            type Error = TestError;

            fn get_key<C: Signing>(
                &self,
                key_request: KeyRequest,
                _secp: &Secp256k1<C>,
            ) -> Result<Option<PrivateKey>, Self::Error> {
                if let Some(ref key_request_to_err) = self.should_error {
                    if key_request == *key_request_to_err {
                        return Err(TestError);
                    }
                }

                match key_request {
                    KeyRequest::Bip32(key_source) => Ok(self.bip32_keys.get(&key_source).copied()),
                    KeyRequest::XOnlyPubkey(xonly) => Ok(self.xonly_keys.get(&xonly).copied()),
                    KeyRequest::Pubkey(pubkey) => Ok(self.public_keys.get(&pubkey.inner).copied()),
                    _ => Ok(None),
                }
            }
        }

        pub fn create_key_source() -> KeySource {
            (
                Fingerprint::from_str("12345678").unwrap(),
                DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap(),
            )
        }

        pub fn create_private_key() -> PrivateKey {
            let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
            PrivateKey::new(secret_key, bitcoin::Network::Bitcoin)
        }
    }

    mod get_taproot_secret {
        use super::key_provider_mock::{create_key_source, create_private_key, MockKeyProvider};
        use crate::send::psbt::get_taproot_secret;
        use bitcoin::{
            bip32::{DerivationPath, Fingerprint},
            psbt::{self, KeyRequest},
            secp256k1::{Secp256k1, XOnlyPublicKey},
        };
        use std::str::FromStr;

        #[test]
        fn empty_tap_key_origins() {
            let secp = Secp256k1::new();
            let psbt_input = psbt::Input::default();
            let key_provider = MockKeyProvider::default();

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert_eq!(result, None);
        }

        #[test]
        fn successful_bip32_key_lookup() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let key_source = create_key_source();
            let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly, (vec![], key_source.clone()));

            let key_provider = MockKeyProvider::default().with_bip32_key(key_source, private_key);

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn fallback_to_xonly_key_lookup() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let key_source = create_key_source();
            let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly, (vec![], key_source.clone()));

            let key_provider = MockKeyProvider::default().with_xonly_key(xonly, private_key);

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn no_keys_found() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly, (vec![], key_source));

            let key_provider = MockKeyProvider::default();

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert_eq!(result, None);
        }

        #[test]
        fn error_in_xonly_lookup() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly, (vec![], key_source.clone()));

            let key_provider =
                MockKeyProvider::default().with_error(KeyRequest::XOnlyPubkey(xonly));

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp);
            assert!(result.is_err());
        }

        #[test]
        fn multiple_origins_first_succeeds() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let key_source1 = create_key_source();
            let key_source2 = (
                Fingerprint::from_str("87654321").unwrap(),
                DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
            );
            let xonly1 = XOnlyPublicKey::from_str(
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            )
            .unwrap();
            let xonly2 = XOnlyPublicKey::from_str(
                "5dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9",
            )
            .unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly1, (vec![], key_source1.clone()));
            psbt_input
                .tap_key_origins
                .insert(xonly2, (vec![], key_source2));

            let key_provider = MockKeyProvider::default().with_bip32_key(key_source1, private_key);

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn multiple_origins_second_succeeds() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let key_source1 = create_key_source();
            let key_source2 = (
                Fingerprint::from_str("87654321").unwrap(),
                DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
            );
            let xonly1 = XOnlyPublicKey::from_str(
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            )
            .unwrap();
            let xonly2 = XOnlyPublicKey::from_str(
                "5dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9",
            )
            .unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .tap_key_origins
                .insert(xonly1, (vec![], key_source1));
            psbt_input
                .tap_key_origins
                .insert(xonly2, (vec![], key_source2.clone()));

            let key_provider = MockKeyProvider::default().with_bip32_key(key_source2, private_key);

            let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }
    }

    mod get_non_taproot_secret {
        use super::key_provider_mock::{create_key_source, create_private_key, MockKeyProvider};
        use crate::send::psbt::get_non_taproot_secret;
        use bitcoin::{
            bip32::{DerivationPath, Fingerprint},
            psbt,
            psbt::KeyRequest,
            secp256k1::{PublicKey, Secp256k1},
        };
        use std::str::FromStr;

        #[test]
        fn empty_bip32_derivation() {
            let secp = Secp256k1::new();
            let psbt_input = psbt::Input::default();
            let key_provider = MockKeyProvider::default();

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert_eq!(result, None);
        }

        #[test]
        fn successful_bip32_key_lookup() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let private_key = create_private_key();
            let public_key = private_key.public_key(&secp).inner;

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key, key_source.clone());

            let key_provider = MockKeyProvider::default().with_bip32_key(key_source, private_key);

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn fallback_to_public_key_lookup() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let private_key = create_private_key();
            let public_key = private_key.public_key(&secp).inner;

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key, key_source.clone());

            let key_provider = MockKeyProvider::default().with_public_key(public_key, private_key);

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn no_keys_found() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let private_key = create_private_key();
            let public_key = private_key.public_key(&secp).inner;

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key, key_source.clone());

            let key_provider = MockKeyProvider::default();

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert_eq!(result, None);
        }

        #[test]
        fn error_in_public_key_lookup() {
            let secp = Secp256k1::new();
            let key_source = create_key_source();
            let private_key = create_private_key();
            let public_key = private_key.public_key(&secp).inner;

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key, key_source.clone());

            let key_provider =
                MockKeyProvider::default().with_error(KeyRequest::Pubkey(public_key.into()));

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp);
            assert!(result.is_err());
        }

        #[test]
        fn multiple_origins_first_succeeds_stop_iteration() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let public_key_1 = private_key.public_key(&secp).inner;
            let public_key_2 = PublicKey::from_str(
                "0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e",
            )
            .unwrap();
            let key_source_1 = create_key_source();
            let key_source_2 = (
                Fingerprint::from_str("87654321").unwrap(),
                DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
            );

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key_1, key_source_1.clone());
            psbt_input
                .bip32_derivation
                .insert(public_key_2, key_source_2.clone());

            let key_provider = MockKeyProvider::default()
                .with_bip32_key(key_source_1, private_key)
                .with_bip32_key(key_source_2, private_key);

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn multiple_origins_second_succeeds_with_public_key() {
            let secp = Secp256k1::new();
            let private_key = create_private_key();
            let public_key_1 = private_key.public_key(&secp).inner;
            let public_key_2 = PublicKey::from_str(
                "0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e",
            )
            .unwrap();
            let key_source_1 = create_key_source();
            let key_source_2 = (
                Fingerprint::from_str("87654321").unwrap(),
                DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
            );

            let mut psbt_input = psbt::Input::default();
            psbt_input
                .bip32_derivation
                .insert(public_key_1, key_source_1.clone());
            psbt_input
                .bip32_derivation
                .insert(public_key_2, key_source_2.clone());

            let key_provider =
                MockKeyProvider::default().with_public_key(public_key_2, private_key);

            let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
            assert!(result.is_some());
        }
    }

    mod update_outputs {
        use super::{
            create_p2tr_input_data, create_test_psbt, get_placeholder_txout, get_sp_derivations,
            setup_sp_codes,
        };
        use crate::send::{error::SpSendError, psbt::update_outputs};
        use bitcoin::{Amount, ScriptBuf, TxOut};
        use std::collections::HashMap;

        #[test]
        fn empty_silent_payments() {
            let original_psbt = create_test_psbt(vec![]);
            let mut psbt = original_psbt.clone();
            let silent_payments = HashMap::new();

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());
            assert_eq!(original_psbt, psbt);
        }

        #[test]
        fn no_matching_placeholder_spk() {
            let sp_codes = setup_sp_codes();
            let non_matching_output = TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            };
            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let mut psbt = create_test_psbt(vec![non_matching_output]);

            let silent_payments = get_sp_derivations(&psbt, &[(spk, priv_key.inner)], &sp_codes);

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());
            assert_eq!(psbt.unsigned_tx.output[0].script_pubkey, ScriptBuf::new());
        }

        #[test]
        fn missing_derivations_error() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];

            let outputs = vec![
                get_placeholder_txout(1000, sp_code),
                get_placeholder_txout(2000, sp_code),
            ];
            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let mut psbt = create_test_psbt(outputs);

            let silent_payments =
                get_sp_derivations(&psbt, &[(spk, priv_key.inner)], &[sp_code.clone()]);

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(matches!(result, Err(SpSendError::MissingDerivations)));
        }

        #[test]
        fn missing_outputs_error() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];

            let outputs = vec![get_placeholder_txout(1000, sp_code)];
            let mut psbt = create_test_psbt(outputs);

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments = get_sp_derivations(
                &psbt,
                &[(spk, priv_key.inner)],
                &[sp_code.clone(), sp_code.clone()],
            );

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(matches!(result, Err(SpSendError::MissingOutputs)));
        }

        #[test]
        fn successful_single_output_update() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];

            let original_value = 1000;
            let outputs = vec![get_placeholder_txout(original_value, sp_code)];
            let mut psbt = create_test_psbt(outputs.clone());

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments =
                get_sp_derivations(&psbt, &[(spk, priv_key.inner)], &[sp_code.clone()]);

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());

            let updated_output = &psbt.unsigned_tx.output[0];
            assert_eq!(updated_output.value, outputs[0].value);

            assert_ne!(updated_output.script_pubkey, outputs[0].script_pubkey);
            assert!(updated_output.script_pubkey.is_p2tr());
        }

        #[test]
        fn multiple_outputs_single_silent_payment_code() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];

            let outputs = vec![
                get_placeholder_txout(1000, sp_code),
                get_placeholder_txout(2000, sp_code),
            ];
            let mut psbt = create_test_psbt(outputs.clone());

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments = get_sp_derivations(
                &psbt,
                &[(spk, priv_key.inner)],
                &[sp_code.clone(), sp_code.clone()],
            );

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());
            for (idx, _) in outputs.iter().enumerate() {
                assert_eq!(psbt.unsigned_tx.output[idx].value, outputs[idx].value);
                assert!(&psbt.unsigned_tx.output[idx].script_pubkey.is_p2tr());
            }
        }

        #[test]
        fn multiple_silent_payment_codes() {
            let sp_codes = setup_sp_codes();
            let sp_code_1 = &sp_codes[0];
            let sp_code_2 = &sp_codes[1];
            let sp_code_3 = &sp_codes[2];

            let outputs = vec![
                get_placeholder_txout(1000, sp_code_1),
                get_placeholder_txout(2000, sp_code_2),
                get_placeholder_txout(3000, sp_code_3),
            ];
            let mut psbt = create_test_psbt(outputs.clone());

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments = get_sp_derivations(
                &psbt,
                &[(spk, priv_key.inner)],
                &[sp_code_1.clone(), sp_code_2.clone(), sp_code_3.clone()],
            );

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());

            for (idx, _) in outputs.iter().enumerate() {
                assert_eq!(psbt.unsigned_tx.output[idx].value, outputs[idx].value);
                assert!(&psbt.unsigned_tx.output[idx].script_pubkey.is_p2tr());
            }
        }

        #[test]
        fn mixed_outputs_some_matching() {
            let sp_codes = setup_sp_codes();
            let sp_code = &sp_codes[0];

            let outputs = vec![
                get_placeholder_txout(1000, sp_code),
                TxOut {
                    value: Amount::from_sat(2000),
                    script_pubkey: ScriptBuf::new(),
                },
            ];
            let mut psbt = create_test_psbt(outputs.clone());

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments =
                get_sp_derivations(&psbt, &[(spk, priv_key.inner)], &[sp_code.clone()]);

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_ok());

            assert_eq!(psbt.unsigned_tx.output[0].value, outputs[0].value);
            assert!(&psbt.unsigned_tx.output[0].script_pubkey.is_p2tr());
            assert_eq!(psbt.unsigned_tx.output[1].script_pubkey, ScriptBuf::new());
        }

        #[test]
        fn early_return_on_first_error() {
            let sp_codes = setup_sp_codes();
            let sp_code_1 = &sp_codes[0];
            let sp_code_2 = &sp_codes[1];

            let outputs = vec![
                get_placeholder_txout(1000, sp_code_1),
                get_placeholder_txout(2000, sp_code_1),
                get_placeholder_txout(3000, sp_code_2),
            ];
            let mut psbt = create_test_psbt(outputs);

            let (priv_key, _, spk, _) = create_p2tr_input_data();
            let silent_payments = get_sp_derivations(
                &psbt,
                &[(spk, priv_key.inner)],
                &[sp_code_1.clone(), sp_code_2.clone()],
            );

            let result = update_outputs(&mut psbt, &silent_payments);

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                SpSendError::MissingDerivations
            ));
        }
    }
}
