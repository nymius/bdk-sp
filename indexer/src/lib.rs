use bdk_chain::{Anchor, BlockId, Merge, TxGraph, TxPosInBlock, tx_graph};
use bdk_sp::{
    bitcoin::{
        Block, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
        key::{
            Secp256k1,
            constants::{GENERATOR_X, GENERATOR_Y},
        },
        secp256k1::{PublicKey, Scalar, SecretKey},
    },
    compute_shared_secret,
    encoding::SilentPaymentCode,
    hashes::get_label_tweak,
    receive::{SpMeta, SpOut, SpReceiveError, scan::Scanner, scan_txouts},
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
    sync::Arc,
};

pub use bdk_chain;

pub struct SpIndexerV2<A> {
    sp_pub: SpPub,
    index: SpIndex,
    graph: TxGraph<A>,
}

impl<A: bdk_chain::Anchor> TryFrom<ChangeSet<A>> for SpIndexerV2<A> {
    type Error = ();
    fn try_from(value: ChangeSet<A>) -> Result<Self, Self::Error> {
        let stage @ ChangeSet {
            scan_sk, spend_pk, ..
        } = value;
        match (scan_sk, spend_pk) {
            (Some(sk), Some(pk)) => {
                let mut indexer = SpIndexerV2::new(pk, sk, SpIndex::default());
                let _ = indexer.apply_changeset(stage);
                Ok(indexer)
            }
            _ => Err(()),
        }
    }
}

impl<A: bdk_chain::Anchor> SpIndexerV2<A> {
    pub fn new(spend_pk: PublicKey, scan_sk: SecretKey, index: SpIndex) -> Self {
        Self {
            sp_pub: SpPub::new(spend_pk, scan_sk),
            index,
            graph: TxGraph::default(),
        }
    }

    pub fn add_label(&mut self, num: u32) -> Option<Label> {
        if let Ok(label) = self.sp_pub.create_label(num) {
            self.index.index_label(&label);
            Some(label)
        } else {
            None
        }
    }

    pub fn get_address(&self, network: Network) -> SilentPaymentCode {
        let secp = Secp256k1::new();
        let scan_pk = self.sp_pub.scan_sk.public_key(&secp);
        SilentPaymentCode::new_v0(self.sp_pub.spend_pk, scan_pk, network)
    }

    pub fn get_labeled_address(&mut self, num: u32, network: Network) -> Option<SilentPaymentCode> {
        let maybe_label_tweak = self
            .index
            .get_label(num)
            .or(self.add_label(num).map(|label| label.tweak));
        let sp_code = self.get_address(network);
        if let Some(label_tweak) = maybe_label_tweak {
            sp_code.add_label(label_tweak).ok()
        } else {
            None
        }
    }

    pub fn scan_sk(&self) -> &SecretKey {
        &self.sp_pub.scan_sk
    }

    pub fn spend_pk(&self) -> &PublicKey {
        &self.sp_pub.spend_pk
    }

    pub fn graph(&self) -> &TxGraph<A> {
        &self.graph
    }

    pub fn index(&self) -> &SpIndex {
        &self.index
    }

    #[allow(unused)]
    fn apply_changeset(&mut self, changeset: ChangeSet<A>) -> ChangeSet<A> {
        let mut initial_changeset = self.initial_changeset();
        if initial_changeset.spend_pk == changeset.spend_pk
            && initial_changeset.scan_sk == changeset.scan_sk
        {
            self.graph.apply_changeset(changeset.graph);
            for (txid, partial_secret) in changeset.txid_to_partial_secret.iter() {
                if let Some(tx) = self.graph.get_tx(*txid) {
                    initial_changeset.merge(self.index_tx(tx.as_ref(), partial_secret));
                }
            }
        }
        initial_changeset
    }

    /// Scans a transaction for relevant outpoints, which are stored and indexed internally.
    pub fn index_tx(&mut self, tx: &Transaction, partial_secret: &PublicKey) -> ChangeSet<A> {
        let mut changeset = ChangeSet::default();
        match self.scan_tx(tx, partial_secret) {
            Ok(spouts) if !spouts.is_empty() => {
                let txid = tx.compute_txid();
                self.index.index_partial_secret(txid, *partial_secret);
                for spout in spouts {
                    self.index.index_spout(spout.outpoint, spout);
                }
                changeset.txid_to_partial_secret = self.index.txid_to_partial_secret.clone();
                changeset.label_lookup = self.index.label_lookup.iter().map(Into::into).collect();
                changeset
            }
            _ => changeset,
        }
    }

    #[allow(unused)]
    pub fn initial_changeset(&self) -> ChangeSet<A> {
        ChangeSet {
            scan_sk: Some(self.sp_pub.scan_sk),
            spend_pk: Some(self.sp_pub.spend_pk),
            txid_to_partial_secret: self.index.txid_to_partial_secret.clone(),
            label_lookup: self.index.label_lookup.iter().map(Into::into).collect(),
            graph: self.graph.initial_changeset(),
        }
    }

    fn is_tx_relevant(&self, tx: &Transaction) -> bool {
        let txid = tx.compute_txid();
        let output_matches = (0..tx.output.len() as u32)
            .map(|vout| OutPoint::new(txid, vout))
            .any(|outpoint| self.index.by_shared_secret.contains_key(&outpoint));
        let input_matches = tx.input.iter().any(|input| {
            self.index
                .by_shared_secret
                .contains_key(&input.previous_output)
        });
        output_matches || input_matches
    }

    fn scan_tx(
        &self,
        tx: &Transaction,
        partial_secret: &PublicKey,
    ) -> Result<Vec<SpOut>, SpReceiveError> {
        let ecdh_shared_secret = compute_shared_secret(&self.sp_pub.scan_sk, partial_secret);
        scan_txouts(
            self.sp_pub.spend_pk,
            &self.index.label_lookup,
            tx,
            ecdh_shared_secret,
        )
    }

    pub fn insert_anchor(&mut self, txid: Txid, anchor: A) -> ChangeSet<A> {
        self.graph.insert_anchor(txid, anchor).into()
    }

    pub fn insert_seen_at(&mut self, txid: Txid, seen_at: u64) -> ChangeSet<A> {
        self.graph.insert_seen_at(txid, seen_at).into()
    }

    pub fn insert_evicted_at(&mut self, txid: Txid, evicted_at: u64) -> ChangeSet<A> {
        self.graph.insert_evicted_at(txid, evicted_at).into()
    }

    pub fn batch_insert_relevant_evicted_at(
        &mut self,
        evicted_ats: impl IntoIterator<Item = (Txid, u64)>,
    ) -> ChangeSet<A> {
        self.graph
            .batch_insert_relevant_evicted_at(evicted_ats)
            .into()
    }

    pub fn batch_insert_relevant<T: Into<Arc<Transaction>>>(
        &mut self,
        txs: impl IntoIterator<Item = (T, PublicKey, impl IntoIterator<Item = A>)>,
    ) -> ChangeSet<A> {
        let txs = txs
            .into_iter()
            .map(|(tx, partial_secret, anchors)| {
                (
                    <T as Into<Arc<Transaction>>>::into(tx),
                    partial_secret,
                    anchors,
                )
            })
            .collect::<Vec<_>>();

        let mut indexer = ChangeSet::default();
        for (tx, partial_secret, _) in &txs {
            indexer.merge(self.index_tx(tx, partial_secret));
        }

        for (tx, _, anchors) in txs {
            if self.is_tx_relevant(&tx) {
                let txid = tx.compute_txid();
                indexer.graph.merge(self.graph.insert_tx(tx.clone()));
                for anchor in anchors {
                    indexer.graph.merge(self.graph.insert_anchor(txid, anchor));
                }
            }
        }

        indexer
    }

    pub fn batch_insert_relevant_unconfirmed<T: Into<Arc<Transaction>>>(
        &mut self,
        unconfirmed_txs: impl IntoIterator<Item = (T, PublicKey, u64)>,
    ) -> ChangeSet<A> {
        let txs = unconfirmed_txs
            .into_iter()
            .map(|(tx, partial_secret, last_seen)| {
                (
                    <T as Into<Arc<Transaction>>>::into(tx),
                    partial_secret,
                    last_seen,
                )
            })
            .collect::<Vec<_>>();

        let mut indexer = ChangeSet::default();
        for (tx, partial_secret, _) in &txs {
            indexer.merge(self.index_tx(tx, partial_secret));
        }

        let relevant_txs: Vec<_> = txs
            .into_iter()
            .filter(|(tx, _, _)| self.is_tx_relevant(tx))
            .map(|(tx, _, seen_at)| (tx.clone(), seen_at))
            .collect();

        indexer.graph = self.graph.batch_insert_unconfirmed(relevant_txs);

        indexer
    }

    pub fn batch_insert_unconfirmed<T: Into<Arc<Transaction>>>(
        &mut self,
        unconfirmed_txs: impl IntoIterator<Item = (T, PublicKey, u64)>,
    ) -> ChangeSet<A> {
        let mut changeset = ChangeSet::default();
        let txs = unconfirmed_txs
            .into_iter()
            .map(|(tx, partial_secret, last_seen)| {
                (
                    <T as Into<Arc<Transaction>>>::into(tx),
                    partial_secret,
                    last_seen,
                )
            })
            .collect::<Vec<_>>();
        let just_txs: Vec<_> = txs
            .clone()
            .into_iter()
            .map(|(tx, _, last_seen)| (tx, last_seen))
            .collect();
        changeset.graph = self.graph.batch_insert_unconfirmed(just_txs);
        for (tx, partial_secret, _) in &txs {
            changeset.merge(self.index_tx(tx, partial_secret));
        }

        changeset
    }
}

impl<A> SpIndexerV2<A>
where
    for<'b> A: Anchor + From<TxPosInBlock<'b>>,
{
    pub fn apply_block_with_filter(
        &mut self,
        block: &Block,
        partial_secrets: HashMap<Txid, PublicKey>,
        height: u32,
        filter: impl Fn(&Self, &Transaction) -> bool,
    ) -> ChangeSet<A> {
        let block_id = BlockId {
            hash: block.block_hash(),
            height,
        };
        let mut changeset = ChangeSet::<A>::default();
        for (tx_pos, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            if let Some(partial_secret) = partial_secrets.get(&txid) {
                changeset.merge(self.index_tx(tx, partial_secret));
                if filter(self, tx) {
                    let anchor = TxPosInBlock {
                        block,
                        block_id,
                        tx_pos,
                    }
                    .into();
                    changeset.graph.merge(self.graph.insert_tx(tx.clone()));
                    changeset
                        .graph
                        .merge(self.graph.insert_anchor(txid, anchor));
                }
            }
        }
        changeset
    }

    pub fn apply_block_relevant(
        &mut self,
        block: &Block,
        partial_secrets: HashMap<Txid, PublicKey>,
        height: u32,
    ) -> ChangeSet<A> {
        self.apply_block_with_filter(block, partial_secrets, height, Self::is_tx_relevant)
    }

    pub fn apply_block(
        &mut self,
        block: &Block,
        partial_secrets: HashMap<Txid, PublicKey>,
        height: u32,
    ) -> ChangeSet<A> {
        self.apply_block_with_filter(block, partial_secrets, height, |_, _| true)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "A: Ord + serde::Deserialize<'de>",
        serialize = "A: Ord + serde::Serialize"
    ))
)]
#[must_use]
pub struct ChangeSet<A> {
    pub scan_sk: Option<SecretKey>,
    pub spend_pk: Option<PublicKey>,
    pub txid_to_partial_secret: BTreeMap<Txid, PublicKey>,
    pub label_lookup: BTreeSet<Label>,
    pub graph: tx_graph::ChangeSet<A>,
}

impl<A> Default for ChangeSet<A> {
    fn default() -> Self {
        Self {
            scan_sk: None,
            spend_pk: None,
            txid_to_partial_secret: BTreeMap::default(),
            label_lookup: BTreeSet::default(),
            graph: Default::default(),
        }
    }
}

impl<A> From<tx_graph::ChangeSet<A>> for ChangeSet<A> {
    fn from(graph: tx_graph::ChangeSet<A>) -> Self {
        Self {
            graph,
            ..Default::default()
        }
    }
}

impl<A: Ord> Merge for ChangeSet<A> {
    fn merge(&mut self, other: Self) {
        if other.scan_sk.is_some() {
            debug_assert!(
                self.scan_sk.is_none() || self.scan_sk == other.scan_sk,
                "scan secret key must never change"
            );
            self.scan_sk = other.scan_sk;
        }
        if other.spend_pk.is_some() {
            debug_assert!(
                self.spend_pk.is_none() || self.spend_pk == other.spend_pk,
                "spend public key must never change"
            );
            self.spend_pk = other.spend_pk;
        }
        // We use `extend` instead of `BTreeMap::append` due to performance issues with `append`.
        // Refer to https://github.com/rust-lang/rust/issues/34666#issuecomment-675658420
        self.txid_to_partial_secret
            .extend(other.txid_to_partial_secret);
        self.label_lookup.extend(other.label_lookup);
        self.graph.merge(other.graph);
    }

    fn is_empty(&self) -> bool {
        self.txid_to_partial_secret.is_empty()
            && self.label_lookup.is_empty()
            && self.graph.is_empty()
    }
}

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

#[derive(Clone, Debug, PartialEq)]
pub struct SpPub {
    spend_pk: PublicKey,
    scan_sk: SecretKey,
}

impl SpPub {
    pub fn new(spend_pk: PublicKey, scan_sk: SecretKey) -> Self {
        Self { spend_pk, scan_sk }
    }

    pub fn create_label(&self, num: u32) -> Result<Label, SpReceiveError> {
        let secp = Secp256k1::verification_only();
        let mut uncompressed_generator_point = [0x04; 65];
        uncompressed_generator_point[1..33].clone_from_slice(&GENERATOR_X);
        uncompressed_generator_point[33..65].clone_from_slice(&GENERATOR_Y);
        let generator_secp256k1 =
            PublicKey::from_slice(&uncompressed_generator_point).map_err(SpReceiveError::from)?;
        let tweak = get_label_tweak(self.scan_sk, num);
        let point = generator_secp256k1
            .add_exp_tweak(&secp, &tweak)
            .map_err(SpReceiveError::from)?;
        Ok(Label { num, tweak, point })
    }
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Label {
    num: u32,
    tweak: Scalar,
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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpIndexes {
    pub by_outpoint: BTreeMap<OutPoint, SpOut>,
    pub by_script: BTreeMap<ScriptBuf, OutPoint>,
    pub by_label: BTreeSet<(Option<u32>, OutPoint)>,
    pub txid_to_partial_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_tweak: BTreeMap<PublicKey, (Scalar, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
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

    pub fn get_by_script(&self, script: &ScriptBuf) -> Option<&SpOut> {
        self.by_script
            .get(script)
            .and_then(|outpoint| self.by_outpoint.get(outpoint))
    }

    pub fn get_by_label(&self, m: Option<u32>) -> impl Iterator<Item = &SpOut> {
        self.by_label
            .iter()
            .filter_map(move |&(maybe_label, outpoint)| {
                if maybe_label == m {
                    self.by_outpoint.get(&outpoint)
                } else {
                    None
                }
            })
    }

    pub fn get_label(&self, m: u32) -> Option<Scalar> {
        if let Some(label_pk) = self.num_to_label.get(&m) {
            self.label_to_tweak.get(label_pk).map(|x| x.0)
        } else {
            None
        }
    }

    pub fn txouts_in_tx(&self, txid: Txid) -> impl DoubleEndedIterator<Item = &SpOut> {
        self.by_outpoint
            .range(OutPoint::new(txid, u32::MIN)..=OutPoint::new(txid, u32::MAX))
            .map(|(_op, spout)| spout)
    }

    pub fn txout(&self, outpoint: OutPoint) -> Option<TxOut> {
        self.by_outpoint.get(&outpoint).map(Into::into)
    }
}

impl From<SpIndexesChangeSet> for SpIndexes {
    fn from(value: SpIndexesChangeSet) -> Self {
        Self {
            by_outpoint: value.by_outpoint,
            by_script: value.by_script,
            txid_to_partial_secret: value.txid_to_partial_secret,
            by_label: value.by_label,
            label_to_tweak: value.label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

impl From<SpIndexes> for SpIndexesChangeSet {
    fn from(value: SpIndexes) -> Self {
        Self {
            by_outpoint: value.by_outpoint,
            by_script: value.by_script,
            txid_to_partial_secret: value.txid_to_partial_secret,
            by_label: value.by_label,
            label_to_tweak: value.label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[must_use]
pub struct SpIndexesChangeSet {
    pub by_outpoint: BTreeMap<OutPoint, SpOut>,
    pub by_script: BTreeMap<ScriptBuf, OutPoint>,
    pub by_label: BTreeSet<(Option<u32>, OutPoint)>,
    pub txid_to_partial_secret: BTreeMap<Txid, PublicKey>,
    #[serde(with = "label_map_serde")]
    pub label_to_tweak: BTreeMap<PublicKey, (Scalar, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
}

impl Merge for SpIndexesChangeSet {
    fn merge(&mut self, other: Self) {
        // We use `extend` instead of `BTreeMap::append` due to performance issues with `append`.
        // Refer to https://github.com/rust-lang/rust/issues/34666#issuecomment-675658420
        self.by_outpoint.extend(other.by_outpoint);
        self.by_script.extend(other.by_script);
        self.txid_to_partial_secret
            .extend(other.txid_to_partial_secret);
        self.by_label.extend(other.by_label);
        self.label_to_tweak.extend(other.label_to_tweak);
        self.num_to_label.extend(other.num_to_label);
    }

    fn is_empty(&self) -> bool {
        self.by_outpoint.is_empty()
            && self.by_script.is_empty()
            && self.txid_to_partial_secret.is_empty()
            && self.by_label.is_empty()
            && self.label_to_tweak.is_empty()
            && self.num_to_label.is_empty()
    }
}

pub struct SpIndexer<A> {
    scanner: Scanner,
    pub indexes: SpIndexes,
    pub tx_graph: TxGraph<A>,
}

impl<A: bdk_chain::Anchor> SpIndexer<A> {
    pub fn new(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
        indexes: SpIndexes,
        tx_graph: TxGraph<A>,
    ) -> Self {
        let scanner = Scanner::new(scan_sk, spend_pk, indexes.clone().label_to_tweak);
        Self {
            scanner,
            indexes,
            tx_graph,
        }
    }

    pub fn is_tx_relevant(&mut self, tx: &Transaction) -> bool {
        let txid = tx.compute_txid();
        let output_matches = (0..tx.output.len() as u32)
            .map(|vout| OutPoint::new(txid, vout))
            .any(|outpoint| self.indexes.by_outpoint.contains_key(&outpoint));
        let input_matches = tx.input.iter().any(|input| {
            self.indexes
                .by_outpoint
                .contains_key(&input.previous_output)
        });
        output_matches || input_matches
    }

    pub fn index_tx(
        &mut self,
        tx: &Transaction,
        partial_secret: &PublicKey,
    ) -> Result<tx_graph::ChangeSet<A>, SpReceiveError> {
        let spouts = self.scanner._scan_tx(tx, partial_secret)?;

        let txid = tx.compute_txid();

        let mut tx_graph_changeset = tx_graph::ChangeSet::<A>::default();
        // Add tx and prevouts to tx_graph
        if !spouts.is_empty() && !self.indexes.txid_to_partial_secret.contains_key(&txid) {
            self.indexes
                .txid_to_partial_secret
                .insert(txid, *partial_secret);
            tx_graph_changeset.merge(self.tx_graph.insert_tx(tx.clone()));
        }

        // Index spouts
        for spout in spouts {
            self.indexes
                .by_outpoint
                .insert(spout.outpoint, spout.clone());

            self.indexes.by_label.insert((spout.label, spout.outpoint));
            self.indexes
                .by_script
                .insert(spout.script_pubkey.clone(), spout.outpoint);
        }

        Ok(tx_graph_changeset)
    }
}
