use self::indexes::{Label, SpIndex};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bdk_chain::{Anchor, BlockId, Merge, TxGraph, TxPosInBlock, tx_graph};
use bdk_sp::{
    bitcoin::{
        Block, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
        key::Secp256k1,
        secp256k1::{PublicKey, Scalar, SecretKey},
    },
    compute_shared_secret,
    encoding::SilentPaymentCode,
    hashes::get_label_tweak,
    receive::{SpOut, SpReceiveError, get_silentpayment_script_pubkey, scan::Scanner, scan_txouts},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    iter::Extend,
    sync::Arc,
};

pub use bdk_chain;
pub mod indexes;

#[derive(Debug, Clone)]
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
            (Some(scan_sk), Some(spend_pk)) => {
                let mut indexer = SpIndexerV2::new(scan_sk, spend_pk);
                indexer.apply_changeset(stage);
                Ok(indexer)
            }
            _ => Err(()),
        }
    }
}

impl<A: bdk_chain::Anchor> SpIndexerV2<A> {
    pub fn new(scan_sk: SecretKey, spend_pk: PublicKey) -> Self {
        Self {
            sp_pub: SpPub::new(scan_sk, spend_pk),
            index: SpIndex::default(),
            graph: TxGraph::default(),
        }
    }

    pub fn add_label(&mut self, num: u32) -> ChangeSet<A> {
        let mut changeset = ChangeSet::default();
        let label = self.sp_pub.create_label(num);
        self.index.index_label(&label);
        changeset.label_lookup.insert(label);
        changeset
    }

    pub fn get_address(&self, network: Network) -> SilentPaymentCode {
        let secp = Secp256k1::signing_only();
        let scan_pk = self.sp_pub.scan_sk.public_key(&secp);
        SilentPaymentCode::new_v0(scan_pk, self.sp_pub.spend_pk, network)
    }

    pub fn get_labeled_address(&mut self, num: u32, network: Network) -> SilentPaymentCode {
        let label_tweak = if let Some(label) = self.index.get_label(num) {
            label
        } else {
            let _ = self.add_label(num);
            self.index.get_label(num).expect("just added")
        };

        let sp_code = self.get_address(network);
        sp_code
            .add_label(label_tweak)
            .expect("computationally unreachable: tweak is the output of a hash function")
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

    pub fn apply_changeset(&mut self, changeset: ChangeSet<A>) {
        if changeset
            .scan_sk
            .is_some_and(|scan_sk| scan_sk == *self.scan_sk())
            && changeset
                .spend_pk
                .is_some_and(|spend_pk| spend_pk == *self.spend_pk())
        {
            self.graph.apply_changeset(changeset.graph);
            changeset.label_lookup.iter().for_each(|label| {
                self.index.index_label(label);
            });
            for (txid, partial_secret) in changeset.txid_to_partial_secret.iter() {
                if let Some(tx) = self.graph.get_tx(*txid) {
                    let _ = self.index_tx(tx.as_ref(), partial_secret);
                }
            }
        }
    }

    pub fn derive_spks_for_tweak(&self, tweak: &PublicKey) -> Vec<[u8; 34]> {
        let ecdh_shared_secret = compute_shared_secret(self.scan_sk(), tweak);

        let mut script_pubkeys = self
            .index()
            .label_lookup
            .keys()
            .map(|label_pk| {
                get_silentpayment_script_pubkey(
                    self.spend_pk(),
                    &ecdh_shared_secret,
                    0u32,
                    Some(label_pk),
                )
            })
            .collect::<Vec<ScriptBuf>>();

        script_pubkeys.push(get_silentpayment_script_pubkey(
            self.spend_pk(),
            &ecdh_shared_secret,
            0u32,
            None,
        ));

        let spk_bytes: Vec<[u8; 34]> = script_pubkeys
            .into_iter()
            .map(|spk| {
                spk.into_bytes()
                    .try_into()
                    .expect("all spks should be p2tr scripts which have 34 bytes")
            })
            .collect();

        spk_bytes
    }

    /// Scans a transaction for relevant outpoints, which are stored and indexed internally.
    pub fn index_tx(&mut self, tx: &Transaction, partial_secret: &PublicKey) -> ChangeSet<A> {
        let mut changeset = ChangeSet::default();
        let ecdh_shared_secret = compute_shared_secret(&self.sp_pub.scan_sk, partial_secret);
        match scan_txouts(
            self.sp_pub.spend_pk,
            &self.index.label_lookup,
            tx,
            ecdh_shared_secret,
        ) {
            Ok(spouts) if !spouts.is_empty() => {
                let txid = tx.compute_txid();
                self.index.index_partial_secret(txid, *partial_secret);
                for spout in spouts {
                    self.index.index_spout(spout.outpoint, spout);
                }
                changeset
                    .txid_to_partial_secret
                    .insert(txid, *partial_secret);
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
        for (tx_pos, tx) in block.txdata.iter().enumerate().skip(1) {
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

#[derive(Clone, Debug, PartialEq)]
pub struct SpPub {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
}

impl SpPub {
    pub fn new(scan_sk: SecretKey, spend_pk: PublicKey) -> Self {
        Self { scan_sk, spend_pk }
    }

    pub fn create_label(&self, num: u32) -> Label {
        let secp = Secp256k1::verification_only();
        let tweak = get_label_tweak(self.scan_sk, num);
        let tweaked_spend_pk = self
            .spend_pk
            .add_exp_tweak(&secp, &tweak)
            .expect("computationally unreachable: tweak is the output of a hash function");
        let negated_spend_pk = self.spend_pk.negate(&secp);
        let point = tweaked_spend_pk.combine(&negated_spend_pk).expect(
            "computationally unreachable: tweaked_spend_pk and spend_pk are valid public keys",
        );
        Label { num, tweak, point }
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

#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
