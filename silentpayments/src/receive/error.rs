#[derive(Debug)]
pub enum SpReceiveError {
    /// The input is not valid for silent payment shared secret derivation
    PubKeyExtractionError(&'static str),
    /// Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
    /// Secp256k1 error
    SliceError(bitcoin::key::FromSliceError),
}

impl From<bitcoin::secp256k1::Error> for SpReceiveError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl From<bitcoin::key::FromSliceError> for SpReceiveError {
    fn from(e: bitcoin::key::FromSliceError) -> Self {
        if let bitcoin::key::FromSliceError::Secp256k1(new_e) = e {
            Self::Secp256k1Error(new_e)
        } else {
            Self::SliceError(e)
        }
    }
}

impl std::fmt::Display for SpReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpReceiveError::PubKeyExtractionError(e) => {
                write!(f, "Silent payment receive error: {e}")
            }
            SpReceiveError::Secp256k1Error(e) => write!(f, "Silent payment receive error: {e}"),
            SpReceiveError::SliceError(e) => write!(f, "Silent payment receive error: {e}"),
        }
    }
}

impl std::error::Error for SpReceiveError {}
