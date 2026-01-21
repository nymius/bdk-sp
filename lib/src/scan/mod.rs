/// Module containing types to support the scanning and indexing of Silent Payment
/// outputs.
use secp256k1::{PublicKey, SecretKey};

/// Metadata associated with a detected Silent payment output.
///
/// When scanning for Silent Payments, this metadata is derived for each
/// output that belongs to the wallet and can be used later for spending.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SpMeta {
    /// The tweak which combined with the spend secret key produces the secret key to unlock this
    /// output.
    pub tweak: SecretKey,
    /// If this output was sent to a labeled code, contains the label number.
    pub label: Option<u32>,
}

/// A Silent Payment scanning key pair used to detect incoming payments.
///
/// This struct holds the scan secret key and spend public key needed to
/// scan the blockchain for Silent Payment outputs addressed to this wallet.
/// The scan secret key is used to compute shared secrets with transaction
/// inputs, while the spend public key is used to verify output ownership.
#[derive(Clone, Debug, PartialEq)]
pub struct SpScan {
    /// The secret key used for scanning transactions.
    scan_sk: SecretKey,
    /// The public key corresponding to the spend secret key.
    spend_pk: PublicKey,
}

impl SpScan {
    /// Creates a new Silent Payment scanner from the given keys.
    pub fn new(scan_sk: SecretKey, spend_pk: PublicKey) -> Self {
        Self { scan_sk, spend_pk }
    }
}
