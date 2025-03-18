use bitcoin::{
    bech32::{
        primitives::{
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

pub struct SilentPaymentCode {
    pub version: u8,
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub network: Network,
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
