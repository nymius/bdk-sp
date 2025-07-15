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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
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
}
