use std::collections::HashMap;

use bdk_chain::bitcoin::{
    self,
    bech32::{
        primitives::{
            iter::{ByteIterExt, Fe32IterExt},
            Bech32m,
        },
        Fe32, Hrp,
    },
    bip32::{DerivationPath, Xpriv},
    hashes::{sha256t_hash_newtype, Hash, HashEngine},
    key::{Parity, TweakedPublicKey},
    secp256k1::{self, ecdh::shared_secret_point, PublicKey, Scalar, SecretKey},
    Amount, CompressedPublicKey, Network, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn,
    TxOut, XOnlyPublicKey,
};

/// Human readable prefix for encoding bitcoin Mainnet silent payment codes
pub const SP: Hrp = Hrp::parse_unchecked("sp");
/// Human readable prefix for encoding bitcoin Testnet (3 or 4) or Signet silent payment codes
pub const TSP: Hrp = Hrp::parse_unchecked("tsp");
/// Human readable prefix for encoding bitcoin regtest silent payment codes
pub const SPRT: Hrp = Hrp::parse_unchecked("sprt");

/// NUM Point used to prune key path spend in taproot
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

pub struct SilentPaymentCode {
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

impl core::fmt::Display for SilentPaymentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hrp = match self.network {
            Network::Bitcoin => self::SP,
            Network::Testnet | Network::Testnet4 | Network::Signet => self::TSP,
            // NOTE: Shouldn't be any other case than Regtest, but add because Network is non
            // exhaustive
            _ => self::SPRT,
        };

        let scan_key_bytes = self.scan.serialize();
        let tweaked_spend_pubkey_bytes = self.spend.serialize();

        let data = [scan_key_bytes, tweaked_spend_pubkey_bytes].concat();

        let version = [self.version]
            .iter()
            .copied()
            .bytes_to_fes()
            .collect::<Vec<Fe32>>()[0];

        let encoded_silent_payment_code = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect::<String>();

        f.write_str(&encoded_silent_payment_code)
    }
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
        outputs: &[(SilentPaymentCode, Amount)],
    ) -> Vec<TxOut> {
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
            .map(|(SilentPaymentCode { scan, spend, .. }, value)| {
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
                let script_pubkey = ScriptBuf::new_p2tr_tweaked(x_only_tweaked);

                // NOTE: Creating the TxOut here is too much?
                // NOTE: Is better to produce a script pubkey and return a match to the address?
                // Does that matter after creating the TxOuts?
                // NOTE: We need a way to match roughly the silent payment address with the amount
                // we wanted to send to them.
                TxOut {
                    script_pubkey,
                    value: *value,
                }
            })
            .collect::<Vec<TxOut>>()
    }
}

#[derive(Debug)]
pub enum PubKeyExtractionError {
    /// The input is not valid
    InvalidInput(&'static str),
    // Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
}

impl From<bitcoin::secp256k1::Error> for PubKeyExtractionError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

pub enum InputsForSharedSecretDerivation {
    P2TR,
    P2WPKH,
    WrappedSegwit,
    P2PKH,
}

pub fn classify_input(
    txin: &TxIn,
    script_pubkey: &ScriptBuf,
) -> Result<InputsForSharedSecretDerivation, PubKeyExtractionError> {
    use InputsForSharedSecretDerivation::*;

    if !txin.witness.is_empty() {
        if !txin.script_sig.is_empty()
            && script_pubkey.is_p2sh()
            && txin
                .script_sig
                .redeem_script()
                .filter(|script| script.is_p2wpkh())
                .is_some()
        {
            Ok(WrappedSegwit)
        } else if !txin.script_sig.is_empty() {
            Err(PubKeyExtractionError::InvalidInput(""))
        } else if script_pubkey.is_p2wpkh() {
            Ok(P2WPKH)
        } else if script_pubkey.is_p2tr() {
            Ok(P2TR)
        } else {
            Err(PubKeyExtractionError::InvalidInput(""))
        }
    } else if !txin.script_sig.is_empty() && script_pubkey.is_p2pkh() {
        Ok(P2WPKH)
    } else {
        Err(PubKeyExtractionError::InvalidInput(""))
    }
}

pub fn get_pubkey_from_input(
    txin: TxIn,
    script_pubkey: &ScriptBuf,
) -> Result<Option<PublicKey>, PubKeyExtractionError> {
    use InputsForSharedSecretDerivation::*;
    match classify_input(&txin, script_pubkey)? {
        WrappedSegwit | P2WPKH => txin
            .witness
            .last()
            // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
            // not considered.
            .map(CompressedPublicKey::from_slice)
            .transpose()?
            .map_or(Err(PubKeyExtractionError::InvalidInput("")), |pubkey| {
                Ok(Some(PublicKey::from_slice(&pubkey.to_bytes()).unwrap()))
            }),
        P2TR => {
            if txin
                .witness
                .taproot_control_block()
                .filter(|control_block| control_block[1..33] == NUMS_H)
                .is_some()
            {
                Ok(None)
            } else {
                Ok(Some(
                    // NOTE: Only x only even taproot keys should be considered
                    XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])?
                        .public_key(Parity::Even),
                ))
            }
        }
        P2PKH => {
            let compressed_pubkey = txin
                .script_sig
                .into_bytes()
                // Is there a compressed pubkey somewhere?
                .windows(33)
                .last()
                // NOTE: This is a way to ensure all used keys are compressed, not compressed keys are
                // not considered.
                .map(CompressedPublicKey::from_slice)
                .transpose()?;

            Ok(compressed_pubkey
                .filter(|pubkey| {
                    <PubkeyHash as AsRef<[u8; 20]>>::as_ref(&pubkey.pubkey_hash())
                        == script_pubkey[3..23].as_bytes()
                })
                .map(|pubkey| PublicKey::from_slice(&pubkey.to_bytes()).unwrap()))
        }
    }
}

pub struct Scanner {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
    label_lookup: HashMap<PublicKey, (Scalar, u32)>,
}

#[derive(Debug)]
pub struct SpOutput {
    pub outpoint: OutPoint,
    pub tweak: Scalar,
    pub public_key: XOnlyPublicKey,
    pub label: Option<u32>,
}

impl Scanner {
    pub fn new(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
        label_lookup: HashMap<PublicKey, (Scalar, u32)>,
    ) -> Self {
        Scanner {
            scan_sk,
            spend_pk,
            label_lookup,
        }
    }

    pub fn scan_tx(&self, tx: &Transaction, prevouts: &[TxOut]) -> Vec<SpOutput> {
        assert_eq!(tx.input.len(), prevouts.len());

        let secp = secp256k1::Secp256k1::new();

        let input_pubkeys: Vec<PublicKey> = tx
            .input
            .clone()
            .into_iter()
            .zip(prevouts)
            .map(|(txin, prevout)| {
                let prevout_spk = prevout.script_pubkey.clone();
                get_pubkey_from_input(txin, &prevout_spk).unwrap_or_default()
            })
            .filter(|x| x.is_some())
            .flatten()
            .collect();

        let input_pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();

        #[allow(non_snake_case)]
        // NOTE: Remember to properly handle all these `unwrap`s
        let A_sum = PublicKey::combine_keys(&input_pubkey_refs).unwrap();
        let smallest_outpoint = tx
            .input
            .iter()
            .map(|txin| {
                let outpoint = txin.previous_output;
                let mut outpoint_bytes = [0u8; 36];
                outpoint_bytes[..32].copy_from_slice(outpoint.txid.to_raw_hash().as_byte_array());
                outpoint_bytes[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
                outpoint_bytes
            })
            .min()
            .unwrap();

        let input_hash = {
            let mut eng = InputsHash::engine();
            eng.input(&smallest_outpoint);
            eng.input(&A_sum.serialize());
            let hash = InputsHash::from_engine(eng);
            // NOTE: Why big endian bytes???
            Scalar::from_be_bytes(hash.to_byte_array())
                .expect("hash value greater than curve order")
        };

        // NOTE: Remember to properly handle all these `unwrap`s
        let partial_ecdh_shared_secret = A_sum.mul_tweak(&secp, &input_hash).unwrap();

        let ecdh_shared_secret = {
            let mut ss_bytes = [0u8; 65];
            ss_bytes[0] = 0x04;

            // Using `shared_secret_point` to ensure the multiplication is constant time
            ss_bytes[1..].copy_from_slice(&shared_secret_point(
                &partial_ecdh_shared_secret,
                &self.scan_sk,
            ));

            PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
        };

        let mut outputs_to_check = {
            let outputs_to_check_even = tx.output.iter().enumerate().filter_map(|(i, txout)| {
                let op = OutPoint {
                    vout: i as u32,
                    txid: tx.compute_txid(),
                };

                if txout.script_pubkey.is_p2tr() {
                    let xonly_pk =
                        XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..]).ok()?;

                    let pk = xonly_pk.public_key(Parity::Even);
                    Some((pk, op))
                } else {
                    None
                }
            });

            let outputs_to_check_odd = outputs_to_check_even
                .clone()
                .map(|(pk, op)| (pk.negate(&secp), op));

            outputs_to_check_even.chain(outputs_to_check_odd)
        };

        let mut sp_outputs_found = <Vec<SpOutput>>::new();
        let mut k = 0_u32;
        let mut loop_count = 0_u32;

        while k == loop_count {
            let t_k = {
                let mut eng = SharedSecretHash::engine();
                eng.input(&ecdh_shared_secret.serialize());
                eng.input(&k.to_le_bytes());
                let hash = SharedSecretHash::from_engine(eng);
                SecretKey::from_slice(&hash.to_byte_array()).unwrap()
            };

            #[allow(non_snake_case)]
            let T_k = t_k.public_key(&secp);

            #[allow(non_snake_case)]
            let P_k = self.spend_pk.combine(&T_k).unwrap();

            if let Some((pk, outpoint)) = outputs_to_check.find(|(pk, _)| P_k == *pk) {
                k += 1;
                sp_outputs_found.push(SpOutput {
                    outpoint,
                    tweak: t_k.into(),
                    public_key: XOnlyPublicKey::from(pk),
                    label: None,
                });
            }

            if let Some(sp_output) = outputs_to_check.find_map(|(pk, outpoint)| {
                let labeled_pk = pk.combine(&P_k.negate(&secp)).unwrap();
                self.label_lookup
                    .get(&labeled_pk)
                    .map(|(tweak, label)| SpOutput {
                        outpoint,
                        tweak: *tweak,
                        public_key: XOnlyPublicKey::from(pk),
                        label: Some(*label),
                    })
            }) {
                k += 1;
                sp_outputs_found.push(sp_output);
            }

            loop_count += 1;
        }

        sp_outputs_found
    }
}
