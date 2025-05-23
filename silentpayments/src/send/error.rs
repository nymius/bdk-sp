#[derive(Debug)]
pub enum SpSendError {
    /// Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
    /// BIP 32 error
    Bip32Error(bitcoin::bip32::Error),
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

impl std::fmt::Display for SpSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpSendError::Bip32Error(e) => write!(f, "Silent payment sending error: {e}"),
            SpSendError::Secp256k1Error(e) => write!(f, "Silent payment sending error: {e}"),
        }
    }
}

impl std::error::Error for SpSendError {}
