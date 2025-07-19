/// # Silent Payments Encoding Module
///
/// This module provides functionality for encoding, decoding, and managing silent payment codes.
/// silent payments are a privacy-enhancing protocol in Bitcoin that allows recipients to receive
/// payments without revealing their addresses or creating any on-chain link between payments.
///
/// The module handles:
/// - Creating and parsing silent payment codes in Bech32m format
/// - Managing scan and spend keys for silent payment codes.
/// - Network-specific encoding with appropriate human-readable prefixes
/// - Version compatibility for forward/backward compatibility
/// - Generating payment scripts from silent payment codes
///
/// silent payment codes follow a structured format with network-specific prefixes:
/// - `sp` for Bitcoin mainnet
/// - `tsp` for Testnet/Signet
/// - `sprt` for Regtest
pub use self::error::{ParseError, UnknownHrpError, VersionError};
use crate::hashes::LabelHash;
use bitcoin::{
    bech32::{
        primitives::{
            decode::CheckedHrpstring,
            iter::{ByteIterExt, Fe32IterExt},
            Bech32m,
        },
        Fe32, Hrp,
    },
    hashes::{sha256, Hash, HashEngine},
    key::{Secp256k1, TweakedPublicKey},
    secp256k1::{PublicKey, Scalar, SecretKey},
    Network, ScriptBuf,
};

pub mod error;

/// Human readable prefix for encoding bitcoin Mainnet silent payment codes
pub const SP: Hrp = Hrp::parse_unchecked("sp");
/// Human readable prefix for encoding bitcoin Testnet (3 or 4) or Signet silent payment codes
pub const TSP: Hrp = Hrp::parse_unchecked("tsp");
/// Human readable prefix for encoding bitcoin regtest silent payment codes
pub const SPRT: Hrp = Hrp::parse_unchecked("sprt");

/// Represents a silent payment code containing the necessary keys and network information.
///
/// A silent payment code consists of:
/// - A version byte indicating the protocol version
/// - A scan public key used for scanning the blockchain for payments
/// - A spend public key used for spending received payments
/// - The Bitcoin network to which this code applies
///
/// Silent payment codes are encoded using [`Bech32m`] with network-specific human-readable prefixes
/// and can be converted to and from string representations.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SilentPaymentCode {
    /// The protocol version (currently the only supported one is v0)
    version: u8,
    /// The public key used for scanning the blockchain for payments
    pub scan: PublicKey,
    /// The public key used for spending received payments
    pub spend: PublicKey,
    /// The Bitcoin network this code is valid for
    pub network: Network,
}

impl SilentPaymentCode {
    /// Creates a new version 0 silent payment code.
    ///
    /// # Arguments
    /// * `scan` - The public key used for scanning the blockchain
    /// * `spend` - The public key used for spending received funds
    /// * `network` - The Bitcoin network this code is valid for
    ///
    /// # Returns
    /// A new [`SilentPaymentCode`] with version 0
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{
    ///     key::rand,
    ///     secp256k1::{PublicKey, Secp256k1},
    ///     Network,
    /// };
    ///
    /// let secp = Secp256k1::new();
    /// let (_, scan_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// let (_, spend_pk) = secp.generate_keypair(&mut rand::thread_rng());
    ///
    /// let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, Network::Bitcoin);
    /// assert_eq!(sp_code.version(), 0);
    /// ```
    pub fn new_v0(scan: PublicKey, spend: PublicKey, network: Network) -> Self {
        SilentPaymentCode {
            version: 0,
            scan,
            spend,
            network,
        }
    }

    /// Generates a scalar from a scan secret key and a numeric label.
    ///
    /// This function creates a deterministic scalar that can be used to tweak the spend key.
    /// It hashes the scan secret key together with a numeric label.
    ///
    /// # Arguments
    /// * `scan_sk` - The scan secret key
    /// * `m` - A 32-bit numeric label
    ///
    /// # Returns
    /// A [`Scalar`] derived from hashing the scan [`SecretKey`] and the numeric label
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{
    ///     key::rand,
    ///     secp256k1::{Secp256k1, SecretKey},
    /// };
    ///
    /// let secp = Secp256k1::new();
    /// let scan_sk = SecretKey::new(&mut rand::thread_rng());
    /// let numeric_label = 42;
    ///
    /// let label = SilentPaymentCode::get_label(scan_sk, numeric_label);
    /// // The label is a deterministic scalar derived from the scan key and the numeric label
    /// ```
    pub fn get_label(scan_sk: SecretKey, m: u32) -> Scalar {
        let mut eng = LabelHash::engine();
        eng.input(&scan_sk.secret_bytes());
        eng.input(&m.to_be_bytes());
        let label = LabelHash::from_engine(eng);
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(label.to_byte_array()).expect("hash value greater than curve order")
    }

    /// Adds a label to the spend key of this silent payment code.
    ///
    /// This function creates a new silent payment code with the spend key tweaked by the given label.
    /// This is used to create labeled codes for different purposes.
    ///
    /// # Arguments
    /// * `label` - The scalar to add to the spend key
    ///
    /// # Returns
    /// A new [`SilentPaymentCode`] with the tweaked spend key
    ///
    /// # Errors
    /// Returns an error if the tweaking operation fails
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{
    ///     key::rand,
    ///     secp256k1::{Scalar, Secp256k1},
    /// };
    ///
    /// // Assuming we have a valid SilentPaymentCode
    /// # let secp = Secp256k1::new();
    /// # let (_, scan_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let (_, spend_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, bitcoin::Network::Bitcoin);
    ///
    /// // Create a label (typically derived from get_label)
    /// let label_bytes = [1u8; 32];
    /// let label = Scalar::from_be_bytes(label_bytes).unwrap();
    ///
    /// // Add the label to the payment code
    /// let labeled_code = sp_code.add_label(label).unwrap();
    /// // The new code has the same scan key but a tweaked spend key
    /// ```
    pub fn add_label(&self, label: Scalar) -> Result<SilentPaymentCode, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::verification_only();

        Ok(SilentPaymentCode {
            spend: self.spend.add_exp_tweak(&secp, &label)?,
            ..self.clone()
        })
    }

    /// Generates a placeholder P2TR script public key for this silent payment code.
    ///
    /// This function creates a Pay-to-Taproot script pubkey that can be used as a placeholder for
    /// the future silent payment final script pubkey. It's derived by tweaking the scan public key
    /// with a hash of the spend public key.
    ///
    /// # Returns
    /// A Pay-to-Taproot script public key [`ScriptBuf`]
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{key::rand, secp256k1::Secp256k1};
    ///
    /// // Assuming we have a valid SilentPaymentCode
    /// # let secp = Secp256k1::new();
    /// # let (_, scan_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let (_, spend_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, bitcoin::Network::Bitcoin);
    ///
    /// let script_pubkey = sp_code.get_placeholder_p2tr_spk();
    /// // script_pubkey can be used as a placeholder output script
    /// ```
    pub fn get_placeholder_p2tr_spk(&self) -> ScriptBuf {
        let secp = Secp256k1::verification_only();
        let spend_hash = sha256::Hash::hash(&self.spend.serialize());
        let placeholder_tweak = Scalar::from_be_bytes(spend_hash.to_byte_array())
            .expect("hash value greater than curve order");
        let pubkey = self.scan.add_exp_tweak(&secp, &placeholder_tweak).expect("computationally unreachable: can only fail if placeholder_tweak = -scan_sk, but placeholder_tweak is the output of a hash function");
        let (x_only_key, _) = pubkey.x_only_public_key();
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);
        ScriptBuf::new_p2tr_tweaked(output_key)
    }

    /// Returns the version of this silent payment code.
    ///
    /// # Returns
    /// The version number as a `u8`
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{key::rand, secp256k1::Secp256k1};
    ///
    /// // Assuming we have a valid SilentPaymentCode
    /// # let secp = Secp256k1::new();
    /// # let (_, scan_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let (_, spend_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, bitcoin::Network::Bitcoin);
    ///
    /// let version = sp_code.version();
    /// assert_eq!(version, 0);
    /// ```
    pub fn version(&self) -> u8 {
        self.version
    }
}

impl core::fmt::Display for SilentPaymentCode {
    /// Formats the silent payment code as a [`Bech32m`] string.
    ///
    /// This implementation encodes the silent payment code using the appropriate
    /// network-specific human-readable prefix and [`Bech32m`] encoding.
    ///
    /// # Arguments
    /// * `f` - The formatter to write to
    ///
    /// # Returns
    /// Nothing on success, a format error otherwise
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    /// use bitcoin::{key::rand, secp256k1::Secp256k1};
    ///
    /// // Assuming we have a valid SilentPaymentCode
    /// # let secp = Secp256k1::new();
    /// # let (_, scan_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let (_, spend_pk) = secp.generate_keypair(&mut rand::thread_rng());
    /// # let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, bitcoin::Network::Bitcoin);
    ///
    /// let encoded = sp_code.to_string();
    /// // encoded is a Bech32m string starting with "sp1"
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hrp = match self.network {
            Network::Bitcoin => SP,
            Network::Testnet | Network::Testnet4 | Network::Signet => TSP,
            // NOTE: Shouldn't be any other case than Regtest, but add because Network is non
            // exhaustive
            _ => SPRT,
        };

        let scan_key_bytes = self.scan.serialize();
        let tweaked_spend_pubkey_bytes = self.spend.serialize();

        let data = [scan_key_bytes, tweaked_spend_pubkey_bytes].concat();

        let version =
            Fe32::try_from(self.version).expect("should be within the GF(32) limits: 0-31");

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

    /// Attempts to parse a string as a silent payment code.
    ///
    /// This implementation decodes a [`Bech32m`] string into a silent payment code,
    /// handling different networks and versions appropriately.
    ///
    /// # Arguments
    /// * `s` - The string to parse
    ///
    /// # Returns
    /// A `Result` containing either the parsed [`SilentPaymentCode`] or a [`ParseError`]
    ///
    /// # Examples
    /// ```rust
    /// use bdk_sp::encoding::SilentPaymentCode;
    ///
    /// // Example of a valid silent payment code string (this is just for illustration)
    /// let sp_code_str = "sp1qkwmj8px0rndxx9euxtx42jf9azw9yk0nqnxnqgx8v3kqpdk0chgk27690g";
    ///
    /// // Parse the string
    /// let result = SilentPaymentCode::try_from(sp_code_str);
    ///
    /// // Check if parsing succeeded
    /// if let Ok(sp_code) = result {
    ///     println!("Successfully parsed silent payment code");
    ///     assert_eq!(sp_code.network, bitcoin::Network::Bitcoin);
    /// } else {
    ///     println!("Failed to parse silent payment code");
    /// }
    /// ```
    fn try_from(s: &str) -> Result<SilentPaymentCode, ParseError> {
        let checked_hrpstring = CheckedHrpstring::new::<Bech32m>(s)?;
        let hrp = checked_hrpstring.hrp();
        let mut payload = checked_hrpstring.fe32_iter::<&mut dyn Iterator<Item = u8>>();

        let version = payload.nth(0).into_iter().collect::<Vec<_>>()[0].to_u8();
        let data = payload.fes_to_bytes().collect::<Vec<u8>>();
        let keys = match version {
            0 => {
                if data.len() != 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data
                }
            }
            1..=30 => {
                if data.len() < 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data.into_iter().take(66).collect::<Vec<u8>>()
                }
            }
            31 => return Err(VersionError::BackwardIncompatibleVersion)?,
            _ => unreachable!("GF(32) values can only belong to the 0-31 range"),
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

        let scan = PublicKey::from_slice(&keys[..33])?;
        let spend = PublicKey::from_slice(&keys[33..66])?;

        Ok(Self {
            scan,
            spend,
            network,
            version,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test {
    use super::SilentPaymentCode;
    use bitcoin::{
        hex::DisplayHex,
        network::Network::Bitcoin,
        secp256k1::{PublicKey, Scalar, SecretKey},
        ScriptBuf,
    };
    use once_cell::sync::Lazy;
    use serde::Deserialize;
    use std::str::FromStr;

    const ENCODING_TEST_VECTORS: &str = r#"
        [
          {
            "index": 0,
            "comment": "successfully parse mainnet code",
            "input": "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734ujpez3s",
            "error": null,
            "output": {
              "version": 0,
              "spend": "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
              "scan": "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b",
              "network": "bitcoin"
            }
          },
          {
            "index": 1,
            "comment": "successfully parse testnet code",
            "input": "tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt",
            "error": null,
            "output": {
              "version": 0,
              "spend": "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
              "scan": "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b",
              "network": "testnet"
            }
          },
          {
            "index": 2,
            "comment": "successfully parse regtest code",
            "input": "sprt1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734u5ddn6e",
            "error": null,
            "output": {
              "version": 0,
              "spend": "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
              "scan": "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b",
              "network": "regtest"
            }
          },
          {
            "index": 3,
            "comment": "fail to parse mainnet code with invalid spend key",
            "input": "sp19q0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqhpj0pezd9rdd9lvdcxz54gcwgph24j020xzu0nxvx6a0gr9u39ce35yz3n50",
            "error": "malformed public key",
            "output": null
          },
          {
            "index": 4,
            "comment": "fail to parse mainnet code with invalid scan key",
            "input": "sp19m66lz4dwzqcqe5vjndhawxr7x40cv8mjgxgzjuylmujqzhnelkgs7qle2fqalvqdr4pw9ay0kuhrrgrtnlgkdswkh5fxfz6pja7a2xu6pvv50l9w",
            "error": "malformed public key",
            "output": null
          },
          {
            "index": 5,
            "comment": "fail to parse code with wrong hrp",
            "input": "bc1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqle2fqalvqdr4pw9ay0kuhrrgrtnlgkdswkh5fxfz6pja7a2xu6pvgqultw",
            "error": "unknown hrp: bc",
            "output": null
          },
          {
            "index": 6,
            "comment": "successfully parse v5 code with data portion above 66 bytes",
            "input": "sp19q0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734ug7pexw6tsec0xextt0qextmudpaenmxyj688a48326cerg99n62kca3jutrxw3efjdytad3dyreupeugcdusgazwad388e6zfcu76056zzuz",
            "error": null,
            "output": {
              "version": 0,
              "spend": "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
              "scan": "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b",
              "network": "bitcoin"
            }
          },
          {
            "index": 7,
            "comment": "fail to parse code with v31",
            "input": "sp1lq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqle2fqalvqdr4pw9ay0kuhrrgrtnlgkdswkh5fxfz6pja7a2xu6pvccpqt4",
            "error": "version 31 codes are not backward compatible",
            "output": null
          },
          {
            "index": 8,
            "comment": "fail to parse v0 mainnet code with invalid data size",
            "error": "payload length does not match version spec",
            "input": "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqle2fqalvqdr4pw9ay0kuhrrgrtnlgkdswkh5fxfz6pja7a2xu6pdcn3286hvtm4jmfp67nnfxfk2ah8wy9t93u5dxs7qd56agnxuujkh27y86v3jlyzp65r47zumz4w4wje869xpaym6qzhxztcef7s4qfrzvyk2",
            "output": null
          },
          {
            "index": 9,
            "comment": "fail to parse v5 mainnet code with short data size",
            "error": "payload length does not match version spec",
            "input": "sp19q0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqknjxnvv",
            "output": null
          },
          {
            "index": 10,
            "comment": "fail to parse mainnet code with invalid checksum",
            "input": "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734ujptzes",
            "error": "invalid checksum",
            "output": null
          }
        ]
    "#;

    static ENCODING_TEST_CASES: Lazy<Vec<EncodingTestCase>> =
        Lazy::new(|| serde_json::from_str(ENCODING_TEST_VECTORS).expect("Invalid JSON"));

    const SCAN_SK: &str = "57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead";
    const SCAN_PK: &str = "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b";
    const SPEND_PK: &str = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";

    #[derive(Debug, Deserialize)]
    struct EncodingTestCase {
        pub index: usize,
        #[serde(alias = "comment")]
        pub _comment: String,
        pub input: String,
        pub output: Option<TestOutput>,
        pub error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct TestOutput {
        #[serde(alias = "version")]
        pub _version: u8,
        pub scan: String,
        pub spend: String,
        pub network: String,
    }

    fn assert_encoding(test_index: usize) {
        let test_case = &ENCODING_TEST_CASES[test_index];
        assert_eq!(test_case.index, test_index);
        if test_case.error.is_some() && test_case.output.is_none() {
            let expected_error = test_case.error.clone().expect("already checked is some");
            let output = SilentPaymentCode::try_from(test_case.input.as_str());
            assert!(output.is_err());
            assert_eq!(expected_error, output.unwrap_err().to_string());
        } else if test_case.output.is_some() {
            let TestOutput {
                scan,
                spend,
                network,
                ..
            } = test_case.output.as_ref().expect("already checked is some");
            let sp_code = SilentPaymentCode::try_from(test_case.input.as_str()).unwrap();
            assert_eq!(scan, &sp_code.scan.to_string());
            assert_eq!(spend, &sp_code.spend.to_string());
            assert_eq!(network, &sp_code.network.to_string());
            // Check roundtrip
            if sp_code.version() == 0 {
                assert_eq!(test_case.input, sp_code.to_string());
            }
        } else {
            panic!("test case definition is wrong");
        }
    }

    fn scan_n_spend_pks() -> (PublicKey, PublicKey) {
        let scan = PublicKey::from_str(SCAN_PK).expect("reading from constant");
        let spend = PublicKey::from_str(SPEND_PK).expect("reading from constant");

        (scan, spend)
    }

    fn scan_sk() -> SecretKey {
        SecretKey::from_str(SCAN_SK).expect("reading from constant")
    }

    #[test]
    fn test_0_successfully_parse_mainnet_code() {
        assert_encoding(0);
    }

    #[test]
    fn test_1_successfully_parse_testnet_code() {
        assert_encoding(1);
    }

    #[test]
    fn test_2_successfully_parse_regtest_code() {
        assert_encoding(2);
    }

    #[test]
    fn test_3_fail_to_parse_mainnet_code_with_invalid_spend_key() {
        assert_encoding(3);
    }

    #[test]
    fn test_4_fail_to_parse_mainnet_code_with_invalid_scan_key() {
        assert_encoding(4);
    }

    #[test]
    fn test_5_fail_to_parse_code_with_wrong_hrp() {
        assert_encoding(5);
    }

    #[test]
    fn test_6_successfully_parse_higher_version_code_with_data_portion_above_66_bytes() {
        assert_encoding(6);
    }

    #[test]
    fn test_7_fail_to_parse_code_with_v31() {
        assert_encoding(7);
    }

    #[test]
    fn test_8_fail_to_parse_v0_mainnet_code_with_invalid_data_size() {
        assert_encoding(8);
    }

    #[test]
    fn fail_to_parse_v5_mainnet_code_with_short_data_size() {
        assert_encoding(9);
    }

    #[test]
    fn fail_to_parse_mainnet_code_with_invalid_checksum() {
        assert_encoding(10);
    }

    #[test]
    fn get_label() {
        let expected_label: &str =
            "6f3cec525b194328307cb10e83c559e29f946cd47e4a9a92eaf55967d9d22cfe";
        let output_label = SilentPaymentCode::get_label(scan_sk(), 4);
        assert_eq!(
            expected_label,
            output_label.to_be_bytes().as_hex().to_string()
        )
    }

    #[test]
    fn get_labelled_sp_code() {
        let expected_labeled_code: &str = "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkq57x0y7k4rs5zkkd7pmumhkdadq7du5t7qf7nkyy6rfzp3jd697cg9zhz0x";
        let expected_labeled_spend_key: &str =
            "029e33c9eb5470a0ad66f83be6ef66f5a0f37945f809f4ec426869106326e8bec2";

        let (scan, spend) = scan_n_spend_pks();
        let sp_code = SilentPaymentCode::new_v0(scan, spend, Bitcoin);
        let label = SilentPaymentCode::get_label(scan_sk(), 4);
        let output_labelled_code = sp_code.add_label(label).expect("should not err");
        assert_eq!(expected_labeled_code, output_labelled_code.to_string());
        assert_eq!(
            expected_labeled_spend_key,
            output_labelled_code.spend.to_string()
        );
        assert_eq!(SCAN_PK, output_labelled_code.scan.to_string())
    }

    #[test]
    fn crafted_labeling_failure_case() {
        let (scan, spend) = scan_n_spend_pks();
        // Use the scan key as spend (because we only have the sk of scan)
        let sp_code = SilentPaymentCode::new_v0(spend, scan, Bitcoin);
        let negated_scan_scalar = Scalar::from(scan_sk().negate());
        let output = sp_code.add_label(negated_scan_scalar);
        assert!(output.is_err());
        assert_eq!("bad tweak", output.unwrap_err().to_string());
    }

    #[test]
    fn check_placeholder_spk() {
        let (scan, spend) = scan_n_spend_pks();
        let expected_placeholder_spk: &str =
            "5120da3d55f0ecf27a3505ded1ac780c3d77299dc4b253010214ac9f2d1d9b365d09";
        let sp_code = SilentPaymentCode::new_v0(scan, spend, Bitcoin);
        let output_placeholder_spk: ScriptBuf = sp_code.get_placeholder_p2tr_spk();
        assert_eq!(
            expected_placeholder_spk,
            output_placeholder_spk.to_hex_string()
        );
    }
}
