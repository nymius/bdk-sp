/// This module provides functionality for encoding, decoding, and managing Silent Payment codes.
///
/// The module handles:
/// - Creating and parsing Silent Payment codes in Bech32m format
/// - Managing scan and spend keys for Silent Payment codes.
/// - Network-specific encoding with appropriate human-readable prefixes
/// - Version compatibility for forward/backward compatibility
///
/// Silent Payment codes follow a structured format with network-specific prefixes:
/// - `sp` for Bitcoin mainnet
/// - `tsp` for Testnet/Signet
/// - `sprt` for Regtest
pub use self::error::{ParseError, UnknownHrpError, VersionError};
use bech32::{
    Fe32, Hrp,
    primitives::{
        Bech32m,
        decode::CheckedHrpstring,
        iter::{ByteIterExt, Fe32IterExt},
    },
};
use bitcoin_network_kind::{Network, TestnetVersion::V4};
use secp256k1::PublicKey;

pub mod error;

/// Human readable prefix for encoding bitcoin Mainnet Silent Payment codes
pub const SP: Hrp = Hrp::parse_unchecked("sp");
/// Human readable prefix for encoding bitcoin Testnet (3 or 4) or Signet Silent Payment codes
pub const TSP: Hrp = Hrp::parse_unchecked("tsp");
/// Human readable prefix for encoding bitcoin regtest Silent Payment codes
pub const SPRT: Hrp = Hrp::parse_unchecked("sprt");

/// Represents a Silent Payment code containing the necessary keys and network information.
///
/// A Silent Payment code consists of:
/// - A version byte indicating the protocol version
/// - A scan public key used for scanning the blockchain for payments
/// - A spend public key used for spending received payments
/// - The Bitcoin network to which this code applies
///
/// Silent payment codes are encoded using [`Bech32m`] with network-specific human-readable prefixes
/// and can be converted to and from string representations.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpCode {
    /// The protocol version (currently the only supported one is v0)
    version: u8,
    /// The public key used for scanning the blockchain for payments
    pub scan: PublicKey,
    /// The public key used for spending received payments
    pub spend: PublicKey,
    /// The Bitcoin network this code is valid for
    pub network: Network,
}

impl SpCode {
    /// Creates a new version 0 Silent Payment code.
    ///
    /// # Arguments
    /// * `scan` - The public key used for scanning the blockchain
    /// * `spend` - The public key used for spending received funds
    /// * `network` - The Bitcoin network this code is valid for
    ///
    /// # Returns
    /// A new [`SpCode`] with version 0
    ///
    /// # Examples
    /// ```rust
    /// use rust_bip352::send::SpCode;
    /// use bitcoin_network_kind::Network;
    /// use secp256k1::{SecretKey, PublicKey};
    ///
    /// # let secret_key = SecretKey::from_byte_array([0xcd; 32]).expect("32 bytes, within curve order");
    /// # let scan_pk = PublicKey::from_secret_key(&secret_key);
    /// # let spend_pk = scan_pk;
    ///
    /// // Generate scan_pk and spend_pk in a secure way.
    ///
    /// let sp_code = SpCode::new_v0(scan_pk, spend_pk, Network::Bitcoin);
    /// assert_eq!(sp_code.version(), 0);
    /// ```
    pub fn new_v0(scan: PublicKey, spend: PublicKey, network: Network) -> Self {
        SpCode {
            version: 0,
            scan,
            spend,
            network,
        }
    }

    /// Returns the version of this Silent Payment code.
    ///
    /// # Returns
    /// The version number as a `u8`
    ///
    /// # Examples
    /// ```rust
    /// use rust_bip352::send::SpCode;
    /// use bitcoin_network_kind::Network;
    /// use secp256k1::{SecretKey, PublicKey};
    ///
    /// # let secret_key = SecretKey::from_byte_array([0xcd; 32]).expect("32 bytes, within curve order");
    /// # let scan_pk = PublicKey::from_secret_key(&secret_key);
    /// # let spend_pk = scan_pk;
    ///
    /// // Assuming we have a valid SpCode
    /// # let sp_code = SpCode::new_v0(scan_pk, spend_pk, Network::Bitcoin);
    ///
    /// let version = sp_code.version();
    /// assert_eq!(version, 0);
    /// ```
    pub fn version(&self) -> u8 {
        self.version
    }
}

impl core::fmt::Display for SpCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hrp = match self.network {
            Network::Bitcoin => SP,
            Network::Testnet(..) | Network::Signet => TSP,
            Network::Regtest => SPRT,
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

impl TryFrom<&str> for SpCode {
    type Error = ParseError;

    /// Attempts to parse a string as a Silent Payment code.
    ///
    /// This implementation decodes a [`Bech32m`] string into a Silent Payment code,
    /// handling different networks and versions appropriately.
    ///
    /// # Arguments
    /// * `s` - The string to parse
    ///
    /// # Errors
    /// Returns [`ParseError`] if the string could not be parsed.
    ///
    /// # Returns
    /// The parsed [`SpCode`].
    ///
    /// # Examples
    /// ```rust
    /// use rust_bip352::send::SpCode;
    /// use bitcoin_network_kind::Network;
    ///
    /// let sp_code_str = "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734ujpez3s";
    ///
    /// let result = SpCode::try_from(sp_code_str);
    ///
    /// if let Ok(sp_code) = result {
    ///     println!("Successfully parsed Silent Payment code");
    ///     assert_eq!(sp_code.network, Network::Bitcoin);
    /// } else {
    ///     println!("Failed to parse Silent Payment code");
    /// }
    /// ```
    fn try_from(s: &str) -> Result<SpCode, ParseError> {
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
            Ok(Network::Testnet(V4))
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
    mod silent_payment_code {
        use crate::send::SpCode;
        use once_cell::sync::Lazy;
        use serde::Deserialize;

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
              "network": "testnet4"
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
                let output = SpCode::try_from(test_case.input.as_str());
                assert!(output.is_err());
                assert_eq!(expected_error, output.unwrap_err().to_string());
            } else if test_case.output.is_some() {
                let TestOutput {
                    scan,
                    spend,
                    network,
                    ..
                } = test_case.output.as_ref().expect("already checked is some");
                let sp_code = SpCode::try_from(test_case.input.as_str()).unwrap();
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

        #[test]
        fn vector_0_successfully_parse_mainnet_code() {
            assert_encoding(0);
        }

        #[test]
        fn vector_1_successfully_parse_testnet_code() {
            assert_encoding(1);
        }

        #[test]
        fn vector_2_successfully_parse_regtest_code() {
            assert_encoding(2);
        }

        #[test]
        fn vector_3_fail_to_parse_mainnet_code_with_invalid_spend_key() {
            assert_encoding(3);
        }

        #[test]
        fn vector_4_fail_to_parse_mainnet_code_with_invalid_scan_key() {
            assert_encoding(4);
        }

        #[test]
        fn vector_5_fail_to_parse_code_with_wrong_hrp() {
            assert_encoding(5);
        }

        #[test]
        fn vector_6_successfully_parse_higher_version_code_with_data_portion_above_66_bytes() {
            assert_encoding(6);
        }

        #[test]
        fn vector_7_fail_to_parse_code_with_v31() {
            assert_encoding(7);
        }

        #[test]
        fn vector_8_fail_to_parse_v0_mainnet_code_with_invalid_data_size() {
            assert_encoding(8);
        }

        #[test]
        fn vector_9_fail_to_parse_v5_mainnet_code_with_short_data_size() {
            assert_encoding(9);
        }

        #[test]
        fn vector_10_fail_to_parse_mainnet_code_with_invalid_checksum() {
            assert_encoding(10);
        }
    }
}
