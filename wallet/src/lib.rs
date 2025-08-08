use bdk_sp::{
    bitcoin::{
        Block, Transaction, Txid,
        absolute::{self, Height, LockTime, Time},
        secp256k1,
    },
    encoding::SilentPaymentCode,
};
use bdk_tx::{
    CanonicalUnspents, InputCandidates, TxStatus, TxWithStatus,
    miniscript::{
        DescriptorPublicKey,
        plan::{Assets, Plan},
    },
};
use indexer::{
    SpIndexerV2 as SpIndexer,
    bdk_chain::{
        Anchor, Balance, CanonicalizationParams, ChainPosition, CheckPoint, ConfirmationBlockTime,
        TxGraph,
        bdk_core::Merge,
        bitcoin::{BlockHash, Network, bip32::DerivationPath, key::Secp256k1},
        local_chain::{self, LocalChain},
        miniscript::{
            Descriptor,
            descriptor::{DescriptorSecretKey, DescriptorType},
        },
    },
};
use std::{collections::HashMap, str::FromStr, sync::Arc};

pub use bdk_tx;
pub mod signers;

#[derive(Default, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[must_use]
pub struct ChangeSet {
    network: Option<Network>,
    chain: local_chain::ChangeSet,
    indexer: indexer::ChangeSet<ConfirmationBlockTime>,
}

impl Merge for ChangeSet {
    fn merge(&mut self, other: Self) {
        if other.network.is_some() {
            debug_assert!(
                self.network.is_none() || self.network == other.network,
                "network must never change"
            );
            self.network = other.network;
        }

        Merge::merge(&mut self.chain, other.chain);
        Merge::merge(&mut self.indexer, other.indexer);
    }

    fn is_empty(&self) -> bool {
        self.network.is_none() && self.chain.is_empty() && self.indexer.is_empty()
    }
}

pub struct SpWallet {
    network: Network,
    chain: LocalChain,
    indexer: SpIndexer<ConfirmationBlockTime>,
    stage: ChangeSet,
}

#[derive(Debug)]
pub enum SpWalletError {
    ReservedLabel,
    PrivateDataNotAvailable,
    NonDefinitiveDescriptor,
    NonTaprootDescriptor,
}

impl SpWallet {
    const CHANGE_LABEL: u32 = 0;
    // Taproot key path spend:
    // scriptSigLen(4) + stackLen(1) + stack[Sig]Len(1) + stack[Sig](65)
    pub const DEFAULT_SPENDING_WEIGHT: u64 = 4 + 1 + 1 + 65;

    pub fn new(
        genesis_hash: BlockHash,
        tr_xprv: &str,
        network: Network,
    ) -> Result<Self, SpWalletError> {
        let scan_derivation = "1h/0";
        let spend_derivation = "0h/0";
        let path = if let Network::Bitcoin = network {
            "352h/0h/0h"
        } else {
            "352h/1h/0h"
        };

        let paths: Vec<DerivationPath> = [scan_derivation, spend_derivation]
            .iter()
            .map(|derivation| format!("{path}/{derivation}"))
            .map(|deriv_str| DerivationPath::from_str(&deriv_str))
            .collect::<Result<Vec<DerivationPath>, _>>()
            .unwrap();

        let secp = Secp256k1::signing_only();
        let (descriptor, keymap) = Descriptor::parse_descriptor(&secp, tr_xprv).unwrap();

        if descriptor.desc_type() != DescriptorType::Tr {
            return Err(SpWalletError::NonTaprootDescriptor);
        }

        if keymap.is_empty() {
            return Err(SpWalletError::PrivateDataNotAvailable);
        }

        let (scan_sk, spend_pk) = match keymap.iter().next().expect("not empty") {
            (_, DescriptorSecretKey::XPrv(privkey)) => {
                let scan_xprv = privkey.xkey.derive_priv(&secp, &paths[0]).unwrap();
                let spend_xprv = privkey.xkey.derive_priv(&secp, &paths[1]).unwrap();
                let scan_sk = scan_xprv.private_key;
                let spend_pk = spend_xprv.private_key.public_key(&secp);
                (scan_sk, spend_pk)
            }
            _ => unimplemented!("only supported single xkeys"),
        };

        let mut indexer = SpIndexer::new(scan_sk, spend_pk);
        let (chain, _) = LocalChain::from_genesis_hash(genesis_hash);

        let mut stage = ChangeSet {
            indexer: indexer.initial_changeset(),
            network: Some(network),
            chain: chain.initial_changeset(),
        };

        stage.indexer.merge(indexer.add_label(Self::CHANGE_LABEL));

        Ok(Self {
            network,
            indexer,
            chain,
            stage,
        })
    }

    pub fn canonical_txs(&self) -> impl Iterator<Item = TxWithStatus<Arc<Transaction>>> + '_ {
        pub fn status_from_position(pos: ChainPosition<ConfirmationBlockTime>) -> Option<TxStatus> {
            match pos {
                ChainPosition::Confirmed { anchor, .. } => Some(TxStatus {
                    height: Height::from_consensus(anchor.confirmation_height_upper_bound())
                        .expect("must convert to height"),
                    time: Time::from_consensus(anchor.confirmation_time as _)
                        .expect("must convert from time"),
                }),
                ChainPosition::Unconfirmed { .. } => None,
            }
        }

        self.indexer
            .graph()
            .list_canonical_txs(
                &self.chain,
                self.chain.tip().block_id(),
                CanonicalizationParams::default(),
            )
            .map(|c_tx| (c_tx.tx_node.tx, status_from_position(c_tx.chain_position)))
    }

    pub fn plan_of_output(&self, assets: &Assets) -> Option<Plan> {
        let single = self.descriptor_placeholder();
        let desc: Descriptor<DescriptorPublicKey> = format!("tr({single})").parse().unwrap();
        let definite_descriptor = desc.at_derivation_index(0).unwrap();
        let plan = definite_descriptor.plan(assets).ok()?;
        Some(plan)
    }

    pub fn assets(&self) -> Assets {
        let tip = self.chain.tip().block_id();
        Assets::new()
            .after(LockTime::from_height(tip.height).expect("must be valid height"))
            .add(self.descriptor_placeholder())
    }

    pub fn all_candidates(&self) -> InputCandidates {
        let assets = self.assets();
        let canon_utxos = CanonicalUnspents::new(self.canonical_txs());
        let can_select = canon_utxos.try_get_unspents(
            self.indexer()
                .index()
                .by_xonly()
                .filter_map(|(_, op)| Some((*op, self.plan_of_output(&assets)?))),
        );
        InputCandidates::new([], can_select)
    }

    // TODO: Use median time to get real tip time
    pub fn tip_info(&self) -> (absolute::Height, absolute::Time) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let current_timestamp = timestamp.as_secs();
        let tip = self.chain.tip().block_id();
        let tip_height = absolute::Height::from_consensus(tip.height).expect("will fix later");
        let tip_time = absolute::Time::from_consensus(current_timestamp.try_into().unwrap())
            .expect("will fix later");
        (tip_height, tip_time)
    }

    pub fn get_address(&self) -> SilentPaymentCode {
        let secp = Secp256k1::signing_only();
        let scan_pk = self.indexer.scan_sk().public_key(&secp);
        SilentPaymentCode::new_v0(scan_pk, *self.indexer.spend_pk(), self.network)
    }

    pub fn get_labelled_address(&mut self, num: u32) -> Result<SilentPaymentCode, SpWalletError> {
        if num == Self::CHANGE_LABEL {
            Err(SpWalletError::ReservedLabel)
        } else {
            let base_sp_code = self.get_address();
            let label = if let Some(label) = self.indexer.index().get_label(num) {
                label
            } else {
                self.stage.indexer.merge(self.indexer.add_label(num));
                self.indexer.index().get_label(num).expect("just added")
            };

            Ok(base_sp_code
                .add_label(label)
                .expect("computationally unreachable: tweak is the output of a hash function"))
        }
    }

    pub fn get_change_address(&mut self) -> SilentPaymentCode {
        let change_label = self
            .indexer
            .index()
            .get_label(Self::CHANGE_LABEL)
            .expect("change label should always be present");
        let base_sp_code = self.get_address();
        base_sp_code
            .add_label(change_label)
            .expect("computationally unreachable: tweak is the output of a hash function")
    }

    pub fn balance(&self) -> Balance {
        let outpoints = self.indexer.index().by_label.clone().into_iter();
        self.indexer.graph().balance(
            &self.chain,
            self.chain.tip().block_id(),
            CanonicalizationParams::default(),
            outpoints,
            |maybe_label: &Option<u32>, _| -> bool { *maybe_label == Some(Self::CHANGE_LABEL) },
        )
    }

    pub fn staged(&self) -> Option<&ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&self.stage)
        }
    }

    pub fn staged_mut(&mut self) -> Option<&mut ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&mut self.stage)
        }
    }

    pub fn take_staged(&mut self) -> Option<ChangeSet> {
        self.stage.take()
    }

    pub fn graph(&self) -> &TxGraph<ConfirmationBlockTime> {
        self.indexer.graph()
    }

    pub fn indexer(&self) -> &SpIndexer<ConfirmationBlockTime> {
        &self.indexer
    }

    pub fn apply_block_relevant(
        &mut self,
        block: &Block,
        partial_secrets: HashMap<Txid, secp256k1::PublicKey>,
        height: u32,
    ) {
        self.stage.indexer.merge(
            self.indexer
                .apply_block_relevant(block, partial_secrets, height),
        )
    }

    pub fn update_chain(&mut self, checkpoint: CheckPoint) {
        self.stage
            .chain
            .merge(self.chain.apply_update(checkpoint).expect("will fix later"));
    }

    pub fn chain(&self) -> &LocalChain {
        &self.chain
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

impl TryFrom<ChangeSet> for SpWallet {
    type Error = ();
    fn try_from(value: ChangeSet) -> Result<Self, Self::Error> {
        if let Some(network) = value.network {
            let chain = LocalChain::from_changeset(value.chain.clone()).map_err(|_| ())?;
            let indexer = SpIndexer::try_from(value.indexer.clone())?;
            Ok(Self {
                network,
                chain,
                indexer,
                stage: value,
            })
        } else {
            Err(())
        }
    }
}
