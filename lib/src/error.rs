use bech32::primitives::decode::CheckedHrpstringError;

/// Error returned when parsing a silent payment code fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The bech32 encoding is invalid.
    Bech32(CheckedHrpstringError),
    /// The version byte is invalid or unsupported.
    Version(VersionError),
    /// The human-readable part is not recognized.
    UnknownHrp(UnknownHrpError),
    /// The public key data is invalid.
    InvalidPubKey(secp256k1::Error),
}

impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bech32(e) => Some(e),
            Self::Version(e) => Some(e),
            Self::UnknownHrp(e) => Some(e),
            Self::InvalidPubKey(e) => Some(e),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Bech32(e) => e.fmt(f),
            Self::Version(e) => e.fmt(f),
            Self::UnknownHrp(e) => e.fmt(f),
            Self::InvalidPubKey(e) => e.fmt(f),
        }
    }
}

impl From<UnknownHrpError> for ParseError {
    fn from(e: UnknownHrpError) -> Self {
        Self::UnknownHrp(e)
    }
}

impl From<VersionError> for ParseError {
    fn from(e: VersionError) -> Self {
        Self::Version(e)
    }
}

impl From<CheckedHrpstringError> for ParseError {
    fn from(e: CheckedHrpstringError) -> Self {
        Self::Bech32(e)
    }
}

impl From<secp256k1::Error> for ParseError {
    fn from(e: secp256k1::Error) -> Self {
        Self::InvalidPubKey(e)
    }
}

/// The human-readable part of the code is not recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHrpError(pub String);

impl core::fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "unknown hrp: {}", self.0)
    }
}

impl core::error::Error for UnknownHrpError {}

/// Error related to the version byte in a silent payment code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    /// Version 31 codes are reserved for future not backward compatible extensions.
    BackwardIncompatibleVersion,
    /// The payload length does not match the expected length for the version.
    WrongPayloadLength,
}

impl core::fmt::Display for VersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::BackwardIncompatibleVersion => {
                write!(f, "version 31 codes are not backward compatible")
            }
            Self::WrongPayloadLength => write!(f, "payload length does not match version spec"),
        }
    }
}

impl core::error::Error for VersionError {}
