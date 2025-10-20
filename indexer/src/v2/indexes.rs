use bdk_sp::{
    bitcoin::{
        secp256k1::{PublicKey, Scalar, SecretKey},
        OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
    },
    receive::{SpMeta, SpOut},
};
#[cfg(feature = "serde")]
use serde::{
    de::{self, Deserializer, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
    Deserialize, Serialize,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
};

/// Represents a specific label used to tweak a Silent Payments address.
///
/// A [`Label`] consists of a numerical identifier, a scalar tweak, and a public key.
/// These are needed to find silent payment outputs sent to labelled silent payment codes.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Label {
    /// The number identifying representing the label for the user.
    pub num: u32,
    /// The [`Scalar`] obtained by combining `num` with the scan secret key.
    pub tweak: Scalar,
    /// A mapping of `tweak` to the secp256k1 elliptic curve.
    pub point: PublicKey,
}

impl From<(&PublicKey, &(Scalar, u32))> for Label {
    fn from(triple: (&PublicKey, &(Scalar, u32))) -> Self {
        let (point, &(tweak, num)) = triple;
        Self {
            num,
            tweak,
            point: *point,
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a 3-tuple: [u32, scalar_bytes, pubkey_bytes]
        let mut tup = serializer.serialize_tuple(3)?;
        tup.serialize_element(&self.num)?;
        tup.serialize_element(&ScalarBytes(self.tweak))?;
        tup.serialize_element(&self.point)?;
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelVisitor;

        impl<'de> Visitor<'de> for LabelVisitor {
            type Value = Label;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (u32, scalar, public_key)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let num = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let tweak = seq
                    .next_element::<ScalarBytes>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?
                    .0;

                let point = seq
                    .next_element::<PublicKey>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                Ok(Label { num, tweak, point })
            }
        }

        deserializer.deserialize_tuple(3, LabelVisitor)
    }
}

#[cfg(feature = "serde")]
pub struct ScalarBytes(pub Scalar);

#[cfg(feature = "serde")]
impl Serialize for ScalarBytes {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        scalar_serde::serialize(&self.0, ser)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ScalarBytes {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        scalar_serde::deserialize(de).map(ScalarBytes)
    }
}

#[cfg(feature = "serde")]
mod scalar_serde {
    use super::Scalar;
    use core::fmt;
    use serde::de::Visitor;
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(s: &Scalar, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_bytes(&s.to_be_bytes())
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Bytes32Visitor;

        impl<'de> Visitor<'de> for Bytes32Visitor {
            type Value = [u8; 32];

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("exactly 32 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != 32 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }

        let bytes = de.deserialize_bytes(Bytes32Visitor)?;
        Scalar::from_be_bytes(bytes).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpIndex {
    pub num_to_label: HashMap<u32, PublicKey>,
    pub by_script: HashMap<ScriptBuf, OutPoint>,
    pub by_label: HashSet<(Option<u32>, OutPoint)>,
    pub by_shared_secret: BTreeMap<OutPoint, SecretKey>,
    // -----------------------------------------------
    pub txid_to_partial_secret: BTreeMap<Txid, PublicKey>,
    pub label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
}

impl SpIndex {
    pub fn index_label(&mut self, label: &Label) {
        let Label { num, tweak, point } = label;
        self.label_lookup.insert(*point, (*tweak, *num));
        self.num_to_label.insert(*num, *point);
    }

    pub fn index_partial_secret(&mut self, txid: Txid, partial_secret: PublicKey) {
        self.txid_to_partial_secret.insert(txid, partial_secret);
    }

    pub fn index_spout(&mut self, outpoint: OutPoint, spout: SpOut) {
        let sp_meta = SpMeta::from(&spout);
        let txout: TxOut = TxOut::from(&spout);
        self.by_shared_secret.insert(outpoint, spout.tweak);
        self.by_script.insert(txout.script_pubkey, outpoint);
        self.by_label.insert((sp_meta.label, outpoint));
    }

    pub fn by_xonly(&self) -> impl Iterator<Item = (XOnlyPublicKey, &OutPoint)> {
        self.by_script.iter().map(|(script_pubkey, outpoint)| {
            let xonly =
                XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..]).expect("p2tr script");
            (xonly, outpoint)
        })
    }

    pub fn get_by_script(&self, script: &ScriptBuf) -> Option<&SecretKey> {
        self.by_script
            .get(script)
            .and_then(|outpoint| self.by_shared_secret.get(outpoint))
    }

    pub fn get_by_label(&self, m: Option<u32>) -> impl Iterator<Item = &SecretKey> {
        self.by_label
            .iter()
            .filter_map(move |&(maybe_label, outpoint)| {
                if maybe_label == m {
                    self.by_shared_secret.get(&outpoint)
                } else {
                    None
                }
            })
    }

    pub fn txouts_in_tx(&self, txid: Txid) -> impl DoubleEndedIterator<Item = &SecretKey> {
        self.by_shared_secret
            .range(OutPoint::new(txid, u32::MIN)..=OutPoint::new(txid, u32::MAX))
            .map(|(_op, spout)| spout)
    }

    pub fn get_label(&self, m: u32) -> Option<Scalar> {
        if let Some(label_pk) = self.num_to_label.get(&m) {
            self.label_lookup.get(label_pk).map(|x| x.0)
        } else {
            None
        }
    }
}
