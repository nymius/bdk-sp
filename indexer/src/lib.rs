use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bdk_chain::{Merge, TxGraph, tx_graph};
use bdk_sp::{
    bitcoin::{
        OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
        key::Secp256k1,
        secp256k1::{PublicKey, Scalar, SecretKey},
    },
    encoding::SilentPaymentCode,
    receive::{SpMeta, SpOut, SpReceiveError, scan::Scanner},
};
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    iter::Extend,
};

pub use bdk_chain;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpIndex {
    pub num_to_label: HashMap<u32, PublicKey>,
    pub by_script: HashMap<ScriptBuf, OutPoint>,
    pub by_label: HashSet<(Option<u32>, OutPoint)>,
    pub by_shared_secret: BTreeMap<OutPoint, SecretKey>,
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

/// Represents a specific label used to tweak a Silent Payments address.
///
/// A [`Label`] consists of a numerical identifier, a scalar tweak, and a public key.
/// These are needed to find silent payment outputs sent to labelled silent payment codes.
#[allow(unused)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Label {
    /// The number identifying representing the label for the user.
    num: u32,
    /// The [`Scalar`] obtained by combining `num` with the scan secret key.
    tweak: Scalar,
    /// A mapping of `tweak` to the secp256k1 elliptic curve.
    point: PublicKey,
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

struct ScalarBytes(pub Scalar);
impl Serialize for ScalarBytes {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        scalar_serde::serialize(&self.0, ser)
    }
}
impl<'de> Deserialize<'de> for ScalarBytes {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        scalar_serde::deserialize(de).map(ScalarBytes)
    }
}
mod scalar_serde {
    use super::Scalar;
    use core::fmt;
    use serde::de::Visitor;
    use serde::{Deserializer, Serializer, de};

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

pub mod label_map_serde {
    use super::{PublicKey, Scalar, ScalarBytes};
    use serde::{
        de::{Deserializer, MapAccess, Visitor},
        ser::{SerializeMap, Serializer},
    };
    use std::{collections::BTreeMap, fmt};

    pub fn serialize<S>(map: &BTreeMap<PublicKey, (Scalar, u32)>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = ser.serialize_map(Some(map.len()))?;
        for (pk, (sc, n)) in map {
            m.serialize_entry(&pk, &(ScalarBytes(*sc), *n))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(de: D) -> Result<BTreeMap<PublicKey, (Scalar, u32)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = BTreeMap<PublicKey, (Scalar, u32)>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map from compressed secp256k1 public keys to (scalar, u32) tuples")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((pk, (sc, n))) =
                    access.next_entry::<PublicKey, (ScalarBytes, u32)>()?
                {
                    map.insert(pk, (sc.0, n));
                }
                Ok(map)
            }
        }

        de.deserialize_map(MapVisitor)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpIndexes {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub script_to_spout: BTreeMap<ScriptBuf, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_spout: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: BTreeMap<PublicKey, (Scalar, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
}

impl SpIndexes {
    pub fn add_label(
        &mut self,
        sp_code: SilentPaymentCode,
        scan_sk: SecretKey,
        m: u32,
    ) -> Result<SilentPaymentCode, SpReceiveError> {
        let secp = Secp256k1::verification_only();
        let label = SilentPaymentCode::get_label(scan_sk, m);
        let labelled_sp_code = sp_code.add_label(label)?;
        let neg_spend_pk = sp_code.spend.negate(&secp);
        #[allow(non_snake_case)]
        // label_G = B_m - B_spend
        let label_G = labelled_sp_code.spend.combine(&neg_spend_pk)?;
        self.label_to_tweak.insert(label_G, (label, m));
        self.num_to_label.insert(m, label_G);
        Ok(labelled_sp_code)
    }

    pub fn get_label(&self, m: u32) -> Option<Scalar> {
        if let Some(label_pk) = self.num_to_label.get(&m) {
            self.label_to_tweak.get(label_pk).map(|x| x.0)
        } else {
            None
        }
    }

    pub fn txouts_in_tx(&self, txid: Txid) -> impl DoubleEndedIterator<Item = &SpOut> {
        self.spouts
            .range(OutPoint::new(txid, u32::MIN)..=OutPoint::new(txid, u32::MAX))
            .map(|(_op, spout)| spout)
    }

    pub fn txout(&self, outpoint: OutPoint) -> Option<TxOut> {
        self.spouts.get(&outpoint).map(Into::into)
    }
}

impl From<SpIndexesChangeSet> for SpIndexes {
    fn from(value: SpIndexesChangeSet) -> Self {
        let label_to_tweak = value
            .label_to_tweak
            .into_iter()
            .map(|(key, (value, m))| (key, (Scalar::from(value), m)))
            .collect();
        Self {
            spouts: value.spouts,
            script_to_spout: value.script_to_spout,
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_spout: value.label_to_spout,
            label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

impl From<SpIndexes> for SpIndexesChangeSet {
    fn from(value: SpIndexes) -> Self {
        let label_to_tweak = value
            .label_to_tweak
            .into_iter()
            .map(|(key, (value, m))| {
                (
                    key,
                    (
                        SecretKey::from_slice(&value.to_be_bytes()).expect("infallible"),
                        m,
                    ),
                )
            })
            .collect();
        Self {
            spouts: value.spouts,
            script_to_spout: value.script_to_spout,
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_spout: value.label_to_spout,
            label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[must_use]
pub struct SpIndexesChangeSet {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub script_to_spout: BTreeMap<ScriptBuf, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_spout: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: BTreeMap<PublicKey, (SecretKey, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
}

impl Merge for SpIndexesChangeSet {
    fn merge(&mut self, other: Self) {
        // We use `extend` instead of `BTreeMap::append` due to performance issues with `append`.
        // Refer to https://github.com/rust-lang/rust/issues/34666#issuecomment-675658420
        self.spouts.extend(other.spouts);
        self.script_to_spout.extend(other.script_to_spout);
        self.txid_to_shared_secret
            .extend(other.txid_to_shared_secret);
        self.label_to_spout.extend(other.label_to_spout);
        self.label_to_tweak.extend(other.label_to_tweak);
        self.num_to_label.extend(other.num_to_label);
    }

    fn is_empty(&self) -> bool {
        self.spouts.is_empty()
            && self.script_to_spout.is_empty()
            && self.txid_to_shared_secret.is_empty()
            && self.label_to_spout.is_empty()
            && self.label_to_tweak.is_empty()
            && self.num_to_label.is_empty()
    }
}

pub struct SpIndexer<T, A> {
    prevout_source: T,
    pub scanner: Scanner,
    pub indexes: SpIndexes,
    pub tx_graph: TxGraph<A>,
}

pub trait PrevoutSource {
    fn get_tx_prevouts(&self, tx: &Transaction) -> Vec<TxOut>;
}

impl<A: bdk_chain::Anchor, T: PrevoutSource> SpIndexer<T, A> {
    pub fn new(
        prevout_source: T,
        scanner: Scanner,
        indexes: SpIndexes,
        tx_graph: TxGraph<A>,
    ) -> Self {
        Self {
            prevout_source,
            scanner,
            indexes,
            tx_graph,
        }
    }

    pub fn spends_owned_spouts(&self, tx: &Transaction) -> bool {
        tx.input
            .iter()
            .any(|input| self.indexes.spouts.contains_key(&input.previous_output))
    }

    pub fn index_tx(&mut self, tx: &Transaction) -> Result<tx_graph::ChangeSet<A>, SpReceiveError> {
        let prevouts = self.prevout_source.get_tx_prevouts(tx);
        let txid = tx.compute_txid();
        let ecdh_shared_secret = self
            .scanner
            .get_shared_secret(tx, &prevouts)
            .expect("infallible");

        let spouts = self.scanner.scan_txouts(tx, ecdh_shared_secret)?;

        let mut tx_graph_changeset = tx_graph::ChangeSet::<A>::default();
        // Add tx and prevouts to tx_graph
        if !spouts.is_empty() && !self.indexes.txid_to_shared_secret.contains_key(&txid) {
            self.indexes
                .txid_to_shared_secret
                .insert(txid, ecdh_shared_secret);
            tx_graph_changeset.merge(self.tx_graph.insert_tx(tx.clone()));
            for (prevout, outpoint) in prevouts
                .iter()
                .zip(tx.input.iter().map(|x| x.previous_output))
            {
                tx_graph_changeset.merge(self.tx_graph.insert_txout(outpoint, prevout.clone()));
            }
        }

        // Index spouts
        for spout in spouts {
            self.indexes.spouts.insert(spout.outpoint, spout.clone());

            self.indexes
                .label_to_spout
                .insert((spout.label, spout.clone()));
            self.indexes
                .script_to_spout
                .insert(spout.script_pubkey.clone(), spout.clone());
        }

        Ok(tx_graph_changeset)
    }
}

pub struct Custom<'a>(pub &'a Client);

impl PrevoutSource for Custom<'_> {
    fn get_tx_prevouts(&self, tx: &Transaction) -> Vec<TxOut> {
        let mut prevouts = <Vec<TxOut>>::new();
        let outpoint_refs = tx.input.iter().map(|x| x.previous_output);
        for OutPoint { txid, vout } in outpoint_refs {
            let prev_tx = self
                .0
                .get_raw_transaction_info(&txid, None)
                .expect("reckless")
                .transaction()
                .expect("reckless");
            let prevout = prev_tx.tx_out(vout as usize).expect("reckless").clone();
            prevouts.push(prevout);
        }
        prevouts
    }
}
