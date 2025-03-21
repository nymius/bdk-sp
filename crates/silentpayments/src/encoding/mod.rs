pub mod error;

pub use self::error::{ParseError, UnknownHrpError, VersionError};

use bitcoin::{
    bech32::{
        primitives::{
            decode::CheckedHrpstring,
            iter::{ByteIterExt, Fe32IterExt},
            Bech32m,
        },
        Fe32, Hrp,
    },
    secp256k1::PublicKey,
    Network,
};
/// Human readable prefix for encoding bitcoin Mainnet silent payment codes
pub const SP: Hrp = Hrp::parse_unchecked("sp");
/// Human readable prefix for encoding bitcoin Testnet (3 or 4) or Signet silent payment codes
pub const TSP: Hrp = Hrp::parse_unchecked("tsp");
/// Human readable prefix for encoding bitcoin regtest silent payment codes
pub const SPRT: Hrp = Hrp::parse_unchecked("sprt");

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SilentPaymentCode {
    pub version: u8,
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub network: Network,
}

impl core::fmt::Display for SilentPaymentCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl TryFrom<&str> for SilentPaymentCode {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<SilentPaymentCode, ParseError> {
        let checked_hrpstring = CheckedHrpstring::new::<Bech32m>(s)?;
        let hrp = checked_hrpstring.hrp();
        let mut payload = checked_hrpstring.fe32_iter::<&mut dyn Iterator<Item = u8>>();

        let version = payload.nth(0).into_iter().collect::<Vec<_>>()[0].to_u8();
        let data = match version {
            0 => {
                let data = payload.fes_to_bytes().collect::<Vec<u8>>();
                if data.len() != 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data
                }
            }
            31 => return Err(VersionError::BackwardIncompatibleVersion)?,
            _ => return Err(VersionError::NotSupported)?,
        };

        let network = if hrp == SP {
            Ok(Network::Bitcoin)
        } else if hrp == TSP {
            Ok(Network::Testnet)
        } else if hrp == SPRT {
            Ok(Network::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }?;

        let scan = PublicKey::from_slice(&data[..33])?;
        let spend = PublicKey::from_slice(&data[33..66])?;

        Ok(Self {
            scan,
            spend,
            network,
            version,
        })
    }
}
