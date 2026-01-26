/// Module containing types to support the scanning and indexing of Silent Payment
/// outputs.
use secp256k1::{PublicKey, SecretKey, silentpayments::recipient as sp_rx};
#[cfg(feature = "serde")]
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
};

/// Represents a specific label used to tweak a Silent Payments code.
///
/// A [`SpLabel`] consists of a numerical identifier, a scalar, and a secp256k1 group element.
/// These are needed to find Silent Payment outputs locked to a labelled Silent Payment code.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct SpLabel {
    /// The number identifying the label for the user.
    pub num: u32,
    /// The scalar obtained by combining and hashing `num` with the scan secret key.
    pub scalar: [u8; 32],
    /// A secp256k1 group element derived from scalar.
    pub ge: sp_rx::Label,
}

impl From<(&sp_rx::Label, &([u8; 32], u32))> for SpLabel {
    fn from(triple: (&sp_rx::Label, &([u8; 32], u32))) -> Self {
        let (ge, &(scalar, num)) = triple;
        Self {
            num,
            scalar,
            ge: *ge,
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for SpLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a 3-tuple: [u32, scalar_bytes, GE bytes]
        let mut tup = serializer.serialize_tuple(3)?;
        tup.serialize_element(&self.num)?;
        tup.serialize_element(&self.scalar)?;
        tup.serialize_element(&self.ge)?;
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SpLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelVisitor;

        impl<'de> Visitor<'de> for LabelVisitor {
            type Value = SpLabel;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a tuple of (u32, scalar, group element)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let num = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let scalar = seq
                    .next_element::<[u8; 32]>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let ge = seq
                    .next_element::<sp_rx::Label>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                Ok(SpLabel { num, scalar, ge })
            }
        }

        deserializer.deserialize_tuple(3, LabelVisitor)
    }
}

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
    pub scan_sk: SecretKey,
    /// The public key corresponding to the spend secret key.
    pub spend_pk: PublicKey,
}

impl SpScan {
    /// Creates a new Silent Payment scanner from the given keys.
    pub fn new(scan_sk: SecretKey, spend_pk: PublicKey) -> Self {
        Self { scan_sk, spend_pk }
    }

    /// Creates a label that can be used to generate distinct Silent Payment codes.
    ///
    /// Labels allow a wallet to have multiple Silent Payment codes that all
    /// derive from the same underlying keys. Each label number produces a unique Silent Payment
    /// code, and the wallet can identify which label was used when receiving a payment.
    ///
    /// # Errors
    /// [sp_rx::LabelError] if label creation fails due to an invalid scalar (very unlikely).
    ///
    /// # Returns
    /// [SpLabel] if succeeds.
    pub fn create_label(&self, num: u32) -> Result<SpLabel, sp_rx::LabelError> {
        let (ge, scalar) = sp_rx::Label::create(&self.scan_sk, num)?;
        Ok(SpLabel { num, scalar, ge })
    }
}
