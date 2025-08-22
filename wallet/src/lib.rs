//! This module provides a [`SpWallet`] struct for managing Silent Payment
//! wallets, including functionalities for address generation, transaction
//! management, and balance tracking.
//!
//! It leverages [`bdk_sp`] for Silent Payments specific logic, [`bdk_tx`] for
//! transaction building, and [`indexer`] for blockchain data management.
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
    bitcoin::XOnlyPublicKey,
    miniscript::{
        DescriptorPublicKey,
        descriptor::{SinglePub, SinglePubKey},
        plan::{Assets, Plan},
    },
};
use indexer::{
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
    v2::SpIndexerV2 as SpIndexer,
};
use std::{collections::HashMap, str::FromStr, sync::Arc};

pub use bdk_tx;
pub mod signers;

/// Represents a set of changes that can be applied to a [`SpWallet`].
///
/// This struct is used to stage updates to the wallet's internal state,
/// including birthday, network, local chain data, and indexer data.
///
/// It implements [`Merge`] to combine multiple change sets.
#[derive(Default, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[must_use]
pub struct ChangeSet {
    /// The starting block height at which this wallet started to operate on.
    birthday: u32,
    /// The Bitcoin network the wallet operates on.
    network: Option<Network>,
    /// Changes related to the local blockchain data.
    chain: local_chain::ChangeSet,
    /// Changes related to the Silent Payments indexer data.
    indexer: indexer::v2::ChangeSet<ConfirmationBlockTime>,
}

impl Merge for ChangeSet {
    /// Merges another [`ChangeSet`] into the current one.
    ///
    /// Changes are applied such that newer or more complete information
    /// overwrites older information. The `network` field is asserted to be
    /// consistent if already set.
    ///
    /// # Arguments
    ///
    /// * `other` - The [`ChangeSet`] to merge from.
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

    /// Checks if the [`ChangeSet`] is empty (contains no changes).
    ///
    /// # Returns
    ///
    /// `true` if the [`ChangeSet`] is empty, `false` otherwise.
    fn is_empty(&self) -> bool {
        self.network.is_none() && self.chain.is_empty() && self.indexer.is_empty()
    }
}

/// A Silent Payment Wallet implementation.
///
/// This struct manages the state and operations of a Silent Payment wallet,
/// including address generation, transaction tracking, balance calculation,
/// and interaction with a blockchain indexer.
pub struct SpWallet {
    /// The birthday of the wallet, representing the starting block height for scanning.
    pub birthday: u32,
    network: Network,
    chain: LocalChain,
    indexer: SpIndexer<ConfirmationBlockTime>,
    stage: ChangeSet,
}

/// Represents errors that can occur during [`SpWallet`] operations.
#[derive(Debug)]
pub enum SpWalletError {
    /// Indicates that the provided label is reserved for internal use.
    ReservedLabel,
    /// Indicates that required private key data is not available.
    PrivateDataNotAvailable,
    /// Indicates that the provided descriptor is not a Taproot descriptor.
    NonTaprootDescriptor,
}

impl SpWallet {
    /// The label reserved for Silent Payments change addresses.
    const CHANGE_LABEL: u32 = 0;
    // Taproot key path spend:
    // scriptSigLen(4) + stackLen(1) + stack[Sig]Len(1) + stack[Sig](65)
    /// Default spending weight for a Taproot key-path spend.
    pub const DEFAULT_SPENDING_WEIGHT: u64 = 4 + 1 + 1 + 65;

    /// Creates a new [`SpWallet`] instance.
    ///
    /// This function initializes the wallet with a birthday, genesis block hash, and a Taproot
    /// extended private key (`tr_xprv`), without derivation paths. It derives the necessary scan
    /// and spend keys for Silent Payments.
    ///
    /// # Arguments
    ///
    /// * `birthday` - The block height or timestamp from which to start scanning the blockchain.
    /// * `genesis_hash` - The hash of the genesis block of the target network.
    /// * `tr_xprv` - The Taproot extended private key string (e.g., `"[<fingerprint>]tprv..."`).
    /// * `network` - The Bitcoin network (e.g., [`Network::Bitcoin`], [`Network::Testnet`]).
    ///
    /// # Returns
    ///
    /// A `Result` indicating success with the new [`SpWallet`] instance, or an [`SpWalletError`]
    /// if initialization fails (e.g., invalid descriptor, missing private data).
    ///
    /// # Errors
    ///
    /// * [`SpWalletError::NonTaprootDescriptor`] if the provided descriptor is not a Taproot descriptor.
    /// * [`SpWalletError::PrivateDataNotAvailable`] if the descriptor cannot provide private key data.
    pub fn new(
        birthday: u32,
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
            birthday,
            indexer: indexer.initial_changeset(),
            network: Some(network),
            chain: chain.initial_changeset(),
        };

        stage.indexer.merge(indexer.add_label(Self::CHANGE_LABEL));

        Ok(Self {
            birthday,
            network,
            indexer,
            chain,
            stage,
        })
    }

    /// Returns an iterator over the canonical transactions in the wallet.
    ///
    /// Canonical transactions are those that are confirmed or those unconfirmed thad doesn't
    /// conflict with other canonical transactions.
    ///
    /// # Returns
    ///
    /// An iterator yielding `TxWithStatus<Arc<Transaction>>` for each canonical transaction.
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

    /// Generates a spending plan for a given [`XOnlyPublicKey`].
    ///
    /// This function creates a [`bdk_tx::miniscript::plan::Plan`] which describes how a Taproot
    /// output controlled by `xonly` can be spent. It assumes a simple Taproot key-path spend,
    /// which will be the case for all BIP 352 compliant wallets.
    ///
    /// # Arguments
    ///
    /// * `xonly` - The [`XOnlyPublicKey`] for which to create the spending plan.
    ///
    /// # Returns
    ///
    /// [`Some<Plan>`], if it can be generated, [`None`] otherwise.
    pub fn spending_plan(&self, xonly: XOnlyPublicKey) -> Option<Plan> {
        let tip = self.chain.tip().block_id();
        let single = DescriptorPublicKey::Single(SinglePub {
            origin: None,
            key: SinglePubKey::XOnly(xonly),
        });
        let desc: Descriptor<DescriptorPublicKey> = format!("tr({single})").parse().unwrap();
        let definite_descriptor = desc.at_derivation_index(0).unwrap();
        let assets = Assets::new()
            .after(LockTime::from_height(tip.height).expect("must be valid height"))
            .add(single);
        let plan = definite_descriptor.plan(&assets).ok()?;
        Some(plan)
    }

    /// Gathers all available input candidates for transaction building.
    ///
    /// This method identifies potential UTXOs from the wallet's known Silent Payment
    /// outputs and prepares them as [`InputCandidates`], which can then be used by
    /// [`bdk_tx`] for coin selection.
    ///
    /// # Returns
    ///
    /// An [`InputCandidates`] struct containing all spendable Silent Payment UTXOs.
    pub fn all_candidates(&self) -> InputCandidates {
        let canon_utxos = CanonicalUnspents::new(self.canonical_txs());
        let unspent_outpoints = self
            .graph()
            .try_filter_chain_unspents(
                self.chain(),
                self.chain().tip().block_id(),
                CanonicalizationParams::default(),
                self.indexer()
                    .index()
                    .by_xonly()
                    .map(|(xonly, outpoint)| (xonly, *outpoint)),
            )
            .unwrap()
            .filter_map(|(xonly, full_txout)| {
                self.spending_plan(xonly)
                    .map(|plan| (full_txout.outpoint, plan))
            });

        let can_select = canon_utxos.try_get_unspents(unspent_outpoints);

        InputCandidates::new([], can_select)
    }

    /// Returns the current tip height and an estimated tip time.
    ///
    /// The height is taken directly from the local chain's tip. For now the
    /// time is the current system time, but should change in the future to receive the
    /// median block time.
    ///
    /// # Returns
    ///
    /// A tuple containing ([`absolute::Height`], [`absolute::Time`]).
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

    /// Returns the base Silent Payment code (address) for this wallet.
    ///
    /// This address is derived from the wallet's scan public key and spend public key,
    /// and does not include any labels. It's the primary receiving address.
    ///
    /// # Returns
    ///
    /// A [`SilentPaymentCode`] representing the wallet's base address.
    pub fn get_address(&self) -> SilentPaymentCode {
        let secp = Secp256k1::signing_only();
        let scan_pk = self.indexer.scan_sk().public_key(&secp);
        SilentPaymentCode::new_v0(scan_pk, *self.indexer.spend_pk(), self.network)
    }

    /// Returns a labelled Silent Payment code (address) for this wallet.
    ///
    /// This function generates a new Silent Payment address with a specific numerical label.
    /// The label helps organize incoming payments. Label `0` is reserved for change addresses.
    /// If the label has not been used before, it will be added to the wallet's staged changes.
    ///
    /// # Arguments
    ///
    /// * `num` - The numerical label to associate with the address. Must not be `0`.
    ///
    /// # Returns
    ///
    /// A [`SilentPaymentCode`] on success.
    ///
    /// # Errors
    ///
    /// * [`SpWalletError::ReservedLabel`] if `num` is `0`.
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

    /// Returns the Silent Payment code (address) for change outputs.
    ///
    /// This address always uses the internally reserved change label.
    ///
    /// # Returns
    ///
    /// A [`SilentPaymentCode`] representing the wallet's change address.
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

    /// Calculates the current balance of the wallet.
    ///
    /// This includes confirmed and unconfirmed (spendable and immature) funds,
    /// differentiating between funds belonging to specific labels and change outputs.
    ///
    /// # Returns
    ///
    /// A [`Balance`] struct containing detailed balance information.
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

    /// Returns an optional reference to the currently staged [`ChangeSet`].
    ///
    /// # Returns
    ///
    /// `Some(&ChangeSet)` if changes are staged, `None` otherwise.
    pub fn staged(&self) -> Option<&ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&self.stage)
        }
    }

    /// Returns an optional mutable reference to the currently staged [`ChangeSet`].
    ///
    /// # Returns
    ///
    /// `Some(&mut ChangeSet)` if changes are staged, `None` otherwise.
    pub fn staged_mut(&mut self) -> Option<&mut ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&mut self.stage)
        }
    }

    /// Takes ownership of the currently staged [`ChangeSet`], leaving an empty [`ChangeSet`] in its place.
    ///
    /// This is useful for atomically applying or persisting the staged changes.
    ///
    /// # Returns
    ///
    /// `Some(ChangeSet)` if changes were staged, `None` otherwise.
    pub fn take_staged(&mut self) -> Option<ChangeSet> {
        self.stage.take()
    }

    /// Returns a reference to the wallet's transaction graph.
    ///
    /// The transaction graph stores all known transactions and their relationships.
    ///
    /// # Returns
    ///
    /// A reference to [`TxGraph<ConfirmationBlockTime>`].
    pub fn graph(&self) -> &TxGraph<ConfirmationBlockTime> {
        self.indexer.graph()
    }

    /// Returns a reference to the wallet's Silent Payments indexer.
    ///
    /// The indexer maintains the Silent Payments specific data, such as shared
    /// secrets and x-only public keys.
    ///
    /// # Returns
    ///
    /// A reference to [`SpIndexer<ConfirmationBlockTime>`].
    pub fn indexer(&self) -> &SpIndexer<ConfirmationBlockTime> {
        &self.indexer
    }

    /// Applies a block's relevant transactions to the wallet's state.
    ///
    /// This function processes a new block, identifying and incorporating any
    /// Silent Payment transactions that belong to this wallet. It updates the
    /// internal indexer and stages the changes.
    ///
    /// # Warning
    ///
    /// This method only stages the changes; you need to [`merge`](Merge::merge) the staged changes
    /// back into the wallet or persist them separately.
    ///
    /// # Arguments
    ///
    /// * `block` - The [`Block`] to process.
    /// * `partial_secrets` - A [`HashMap`] mapping [`Txid`] to [`secp256k1::PublicKey`] for
    ///   transactions where a partial secret is known. This is crucial for Silent Payments
    ///   to derive full shared secrets.
    /// * `height` - The height of the `block` being applied.
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

    /// Updates the local chain with a new [`CheckPoint`].
    ///
    /// This function advances the wallet's understanding of the blockchain,
    /// typically by adding new blocks or reorg information. The changes are
    /// staged.
    ///
    /// # Arguments
    ///
    /// * `checkpoint` - The [`CheckPoint`] representing the latest chain state.
    pub fn update_chain(&mut self, checkpoint: CheckPoint) {
        self.stage
            .chain
            .merge(self.chain.apply_update(checkpoint).expect("will fix later"));
    }

    /// Returns a reference to the wallet's local blockchain.
    ///
    /// # Returns
    ///
    /// A reference to [`LocalChain`].
    pub fn chain(&self) -> &LocalChain {
        &self.chain
    }

    /// Returns the network the wallet is configured for.
    ///
    /// # Returns
    ///
    /// A [`Network`] enum value.
    pub fn network(&self) -> Network {
        self.network
    }
}

impl TryFrom<ChangeSet> for SpWallet {
    type Error = ();

    /// Attempts to create an [`SpWallet`] from a [`ChangeSet`].
    ///
    /// This is useful for restoring a wallet's state from persisted changes.
    /// It requires the `network` to be present in the [`ChangeSet`].
    ///
    /// # Arguments
    ///
    /// * `value` - The [`ChangeSet`] to convert into an [`SpWallet`].
    ///
    /// # Returns
    ///
    /// A `Result` indicating success with the new [`SpWallet`] instance, or `()`
    /// if the conversion fails (e.g., missing network information, invalid change data).
    // TODO: Improve the Error returned
    fn try_from(value: ChangeSet) -> Result<Self, Self::Error> {
        if let Some(network) = value.network {
            let chain = LocalChain::from_changeset(value.chain.clone()).map_err(|_| ())?;
            let indexer = SpIndexer::try_from(value.indexer.clone())?;
            Ok(Self {
                birthday: value.birthday,
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
