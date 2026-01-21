/// This library provides a small set of structs and methods to help in the implementation of the
/// Silent Payments protocol.
///
/// Silent Payments are a privacy-enhancing protocol in Bitcoin that allows recipients to receive
/// payments without revealing their code or creating any on-chain link between payments.
///
/// This library **does not implement** the cryptographic primitives required for the full
/// implementation of Silent Payments.
pub mod scan;
pub mod send;

use bitcoin_primitives::OutPoint;

/// Error type returned when attempting to retrieve the minimum outpoint
/// from a [`LexMin`] that has not received any updates.
///
/// This error indicates that [`LexMin::bytes`] was called before any
/// outpoints were provided via [`LexMin::update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoMinOutpoint;

impl core::error::Error for NoMinOutpoint {}

impl core::fmt::Display for NoMinOutpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "No minimal outpoint, update at least once")
    }
}

/// A structure for tracking the lexicographically minimal [`OutPoint`].
///
/// `LexMin` maintains a reference to the smallest outpoint seen so far, using lexicographic
/// comparison. The comparison first orders by Txid bytes, then by output index in little-endian
/// byte order.
///
/// # Lifetime
/// The `'a` lifetime parameter ensures that the tracked outpoint references
/// remain valid for the duration of the `LexMin` instance.
///
/// # Example
/// ```rust
/// # use rust_bip352::LexMin;
/// # use bitcoin_primitives::{Txid, OutPoint};
/// let mut tracker = LexMin::default();
///
/// let outpoint1 = OutPoint {
///     txid: Txid::from_byte_array([8u8; 32]),
///     vout: 0,
/// };
/// let outpoint2 = OutPoint {
///     txid: Txid::from_byte_array([5u8; 32]),
///     vout: 100,
/// };
///
/// tracker.update(&outpoint1);
/// tracker.update(&outpoint2);
///
/// let min_bytes = tracker.bytes().expect("updated at least once");
/// ```
#[derive(Default)]
pub struct LexMin<'a> {
    /// The current minimum outpoint, or `None` if no outpoints have been provided.
    current_min: Option<&'a OutPoint>,
}

impl<'a> LexMin<'a> {
    /// Updates the tracker with a new outpoint and returns the current minimum.
    ///
    /// Compares the provided `outpoint` with the current minimum using
    /// lexicographic ordering:
    /// 1. First, compares txids as byte arrays
    /// 2. If txids are equal, compares output indices as little-endian bytes
    ///
    /// # Arguments
    /// * `outpoint` - A reference to the outpoint to compare against the current minimum.
    ///
    /// # Returns
    /// A reference to the lexicographically smallest outpoint seen so far,
    /// including the newly provided one.
    pub fn update(&mut self, outpoint: &'a OutPoint) -> &'a OutPoint {
        if let Some(min) = self.current_min {
            let new_min = core::cmp::min_by(outpoint, min, |a, b| {
                // Compare txids first
                let a_txid = a.txid.to_byte_array();
                let b_txid = b.txid.to_byte_array();

                // If txids are different, compare them
                match a_txid.cmp(&b_txid) {
                    core::cmp::Ordering::Equal => {
                        // If txids are equal, compare vouts directly
                        let a_vout_bytes = a.vout.to_le_bytes();
                        let b_vout_bytes = b.vout.to_le_bytes();
                        a_vout_bytes.cmp(&b_vout_bytes)
                    }
                    other => other,
                }
            });
            self.current_min = Some(new_min);
            new_min
        } else {
            self.current_min = Some(outpoint);
            outpoint
        }
    }

    /// Returns the 36-byte serialized representation of the minimum outpoint.
    ///
    /// The format is:
    /// - bytes `[0..32]`: Txid as a byte array
    /// - bytes `[32..36]`: Output index as little-endian `u32`
    ///
    /// # Errors
    /// Returns [`NoMinOutpoint`] if [`LexMin::update`] has never been called.
    ///
    /// # Returns
    /// A 36-byte array containing the serialized minimum outpoint.
    pub fn bytes(&self) -> Result<[u8; 36], NoMinOutpoint> {
        if let Some(min) = self.current_min {
            let mut result = [0u8; 36];
            result[..32].copy_from_slice(&min.txid.to_byte_array());
            result[32..36].copy_from_slice(&min.vout.to_le_bytes());

            Ok(result)
        } else {
            Err(NoMinOutpoint)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test {
    mod lex_min {
        use crate::LexMin;
        use bitcoin_primitives::{OutPoint, Txid};

        #[test]
        fn different_txids_and_vouts() {
            let mut lex_min = LexMin::default();
            let outpoints = [
                OutPoint {
                    txid: Txid::from_byte_array([3u8; 32]),
                    vout: 2,
                },
                OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 1,
                },
                OutPoint {
                    txid: Txid::from_byte_array([5u8; 32]),
                    vout: 3,
                },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [2u8; 36];
            expected_bytes[32..36].copy_from_slice(&1u32.to_le_bytes());

            assert_eq!(result, expected_bytes);
        }

        #[test]
        fn fail_if_not_updated() {
            let e = LexMin::default().bytes().expect_err("should fail");
            assert_eq!("No minimal outpoint, update at least once", e.to_string());
        }

        #[test]
        fn identical_txid_different_vouts() {
            let mut lex_min = LexMin::default();
            let txid = Txid::from_byte_array([0u8; 32]);
            let outpoints = [
                OutPoint { txid, vout: 10 },
                OutPoint { txid, vout: 2 },
                OutPoint { txid, vout: 5 },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [0u8; 36];
            expected_bytes[32..36].copy_from_slice(&2u32.to_le_bytes());
            assert_eq!(result, expected_bytes);
        }

        #[test]
        fn same_vout_different_txid() {
            let mut lex_min = LexMin::default();
            let outpoints = [
                OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 7,
                },
                OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 7,
                },
                OutPoint {
                    txid: Txid::from_byte_array([3u8; 32]),
                    vout: 7,
                },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [1u8; 36];
            expected_bytes[32..36].copy_from_slice(&7u32.to_le_bytes());
            assert_eq!(result, expected_bytes);
        }

        #[test]
        fn edge_case_vout_is_u32_max() {
            let mut lex_min = LexMin::default();
            let outpoints = [
                OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: u32::MAX,
                },
                OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: u32::MIN,
                },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [1u8; 36];
            expected_bytes[..32].copy_from_slice(&[1u8; 32]);
            expected_bytes[32..36].copy_from_slice(&u32::MIN.to_le_bytes());
            assert_eq!(result, expected_bytes);
        }

        #[test]
        fn txid_takes_precedence() {
            let mut lex_min = LexMin::default();
            let outpoints = [
                OutPoint {
                    txid: Txid::from_byte_array([8u8; 32]),
                    vout: 0,
                },
                OutPoint {
                    txid: Txid::from_byte_array([5u8; 32]),
                    vout: 100,
                },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [5u8; 36];
            expected_bytes[32..36].copy_from_slice(&100u32.to_le_bytes());
            assert_eq!(result, expected_bytes);
        }

        #[test]
        fn txid_endianness_matters() {
            let mut lex_min = LexMin::default();
            // big endian: 0x[00][00][00][01]
            // big endian: 0x[a1][b1][c1][d1]
            let mut txid_bytes_be = [0u8; 32];
            txid_bytes_be[0] = 1;

            // little endian: 0x[01][00][00][00]
            // little endian: 0x[a2][b2][c2][d2]
            let mut txid_bytes_le = [0u8; 32];
            txid_bytes_le[31] = 1;

            let outpoints = [
                OutPoint {
                    txid: Txid::from_byte_array(txid_bytes_be),
                    vout: 1,
                },
                OutPoint {
                    txid: Txid::from_byte_array(txid_bytes_le),
                    vout: 1,
                },
            ];

            for outpoint in outpoints.iter() {
                lex_min.update(outpoint);
            }

            // if Txid is big endian then: [a1] < [a2] => expected_bytes = txid_bytes_be
            // if Txid is little endian then: [d2] < [d1] => expected_bytes = txid_bytes_le
            let result = lex_min.bytes().expect("should succeed");

            let mut expected_bytes = [0u8; 36];
            // Txid is little endian
            expected_bytes[31] = 1;
            expected_bytes[32..36].copy_from_slice(&1u32.to_le_bytes());

            assert_eq!(result, expected_bytes);
        }
    }
}
