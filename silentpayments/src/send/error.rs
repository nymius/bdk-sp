#[derive(Debug)]
pub enum SpSendError {
    /// Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
    /// BIP 32 error
    Bip32Error(bitcoin::bip32::Error),
    /// No available inputs for shared secret derivation
    MissingInputsForSharedSecretDerivation,
    /// PSBT missing witness
    MissingWitness,
    /// PSBT missing prevout
    MissingPrevout,
    /// Output out of bounds
    IndexError(bitcoin::blockdata::transaction::OutputsIndexError),
    /// PSBT missing silent payment placeholder script
    MissingPlaceholderScript,
}

impl From<bitcoin::secp256k1::Error> for SpSendError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl From<bitcoin::bip32::Error> for SpSendError {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Self::Bip32Error(e)
    }
}

impl From<bitcoin::blockdata::transaction::OutputsIndexError> for SpSendError {
    fn from(e: bitcoin::blockdata::transaction::OutputsIndexError) -> Self {
        Self::IndexError(e)
    }
}

impl std::fmt::Display for SpSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bip32Error(e) => write!(f, "Silent payment sending error: {e}"),
            Self::Secp256k1Error(e) => write!(f, "Silent payment sending error: {e}"),
            Self::IndexError(e) => write!(f, "From PSBT: {e}"),
            Self::MissingInputsForSharedSecretDerivation => write!(f, "No available inputs for shared secret derivation"),
            Self::MissingWitness => write!(
                f,
                "From PSBT, missing witness to get public key to derive silent payment output"
            ),
            Self::MissingPrevout => write!(f, "From PSBT, unable to extract prevout script pubkey"),
            Self::MissingPlaceholderScript => write!(f, "From PSBT, missing placeholder script pubkey for associated silent payment recipient."),
        }
    }
}

impl std::error::Error for SpSendError {}
