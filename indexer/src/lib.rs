pub use bdk_chain;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::Extend;

use bdk_chain::{Merge, TxGraph, tx_graph};

use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::{
    bitcoin::{
        OutPoint, Transaction, TxOut, Txid,
        secp256k1::{PublicKey, Scalar, SecretKey},
    },
    receive::{SpOut, SpReceiveError, scan::Scanner},
};

use bitcoin::ScriptBuf;
use bitcoin::key::Secp256k1;

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
    use super::{PublicKey, Scalar, scalar_serde};
    use serde::{
        Deserialize, Serialize,
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
