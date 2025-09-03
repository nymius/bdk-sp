use anyhow::{self, bail, Context};
use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client, RpcApi},
    Emitter, NO_EXPECTED_MEMPOOL_TXIDS,
};
use bdk_file_store::Store;
use bdk_sp::{
    bitcoin::{
        self,
        address::NetworkUnchecked,
        bip32,
        consensus::Decodable,
        hex::{DisplayHex, FromHex},
        key::Secp256k1,
        script::PushBytesBuf,
        secp256k1::{PublicKey, Scalar},
        Address, Amount, Block, BlockHash, FeeRate, Network, OutPoint, PrivateKey, ScriptBuf,
        Sequence, Transaction, TxOut, Txid,
    },
    compute_shared_secret,
    encoding::SilentPaymentCode,
    receive::{compute_tweak_data, get_silentpayment_script_pubkey},
    send::psbt::{
        derive_sp,
        sign::{add_sp_data_to_input, sign_sp},
    },
};
use bdk_sp_oracles::{
    filters::kyoto::{FilterEvent, FilterSubscriber},
    kyoto::{
        self,
        tokio::{self, select},
        AddrV2, Client as KyotoClient, HeaderCheckpoint, IndexedBlock, Info, NodeBuilder,
        ServiceFlags, TrustedPeer, UnboundedReceiver, Warning,
    },
    tweaks::blindbit::{BlindbitSubscriber, TweakEvent},
};
use bdk_sp_wallet::{
    bdk_tx::{
        self, filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, Output,
        PsbtParams, SelectorParams,
    },
    signers::get_spend_sk,
    ChangeSet, SpWallet,
};
use clap::{self, ArgGroup, Args, Parser, Subcommand};
use indexer::bdk_chain::BlockId;
use rand::RngCore;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

const DB_MAGIC: &[u8] = b"bdk_example_silentpayments";

/// Delay for printing status to stdout.
const STDOUT_PRINT_DELAY: Duration = Duration::from_secs(6);
/// Delay for committing to persistence.
const DB_COMMIT_DELAY: Duration = Duration::from_secs(60);

fn parse_recipients(s: &str) -> Result<(Address<NetworkUnchecked>, u64), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid format '{}'. Expected 'key:value'", s));
    }

    let value_0 = parts[0].trim();
    let address = Address::<NetworkUnchecked>::from_str(value_0)
        .map_err(|_| format!("Invalid address: {}", value_0))?;
    let value = parts[1]
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid number '{}' for key '{}'", parts[1], value_0))?;
    Ok((address, value))
}

fn parse_sp_recipients(s: &str) -> Result<(SilentPaymentCode, u64), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid format '{}'. Expected 'key:value'", s));
    }

    let value_0 = parts[0].trim();
    let key = SilentPaymentCode::try_from(value_0)
        .map_err(|_| format!("Invalid silent payment address: {}", value_0))?;

    let value = parts[1]
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid number '{}' for key '{}'", parts[1], key))?;

    Ok((key, value))
}

#[derive(Args, Debug, Clone)]
pub struct RpcArgs {
    /// RPC URL
    #[clap(env = "RPC_URL", long, default_value = "127.0.0.1:8332")]
    url: String,
    /// RPC auth username
    #[clap(env = "RPC_USER", long)]
    rpc_user: Option<String>,
    /// RPC auth password
    #[clap(env = "RPC_PASS", long)]
    rpc_password: Option<String>,
}

impl RpcArgs {
    fn new_client(&self) -> anyhow::Result<Client> {
        Ok(Client::new(
            &self.url,
            match (&self.rpc_user, &self.rpc_password) {
                (None, None) => Auth::None,
                (Some(user), Some(pass)) => Auth::UserPass(user.clone(), pass.clone()),
                (Some(_), None) => panic!("rpc auth: missing rpc_pass"),
                (None, Some(_)) => panic!("rpc auth: missing rpc_user"),
            },
        )?)
    }
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct SpArgs {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    #[command(group(
    ArgGroup::new("txid or transaction hex is required")
        .args(["tx_hex", "txid"])
        .required(true)
        .multiple(false)
    ))]
    DeriveSpForTx {
        #[clap(flatten)]
        rpc_args: RpcArgs,
        order: u32,
        #[clap(long)]
        txid: Option<Txid>,
        #[clap(long)]
        tx_hex: Option<String>,
        #[clap(long)]
        label: Option<u32>,
    },
    ScanCbf {
        tweak_server_url: String,
    },
    Create {
        /// Network
        #[clap(long, short, default_value = "signet")]
        network: Network,
        /// The block height at which to begin scanning outputs for this wallet
        #[clap(long, short, default_value = "signet")]
        birthday: u32,
        /// Genesis Hash
        genesis_hash: Option<BlockHash>,
    },
    Code {
        #[clap(long)]
        label: Option<u32>,
    },
    /// Use bitcoind RPC to scan the blockchain looking for silent payment outputs belonging to the
    /// provided silent payment code
    ScanRpc {
        #[clap(flatten)]
        rpc_args: RpcArgs,
    },
    #[command(group(
    ArgGroup::new("at least one recipient is required")
        .args(["addresses", "sp_codes"])
        .required(true)
    ))]
    NewTx {
        /// Recipient address
        #[clap(long = "to", value_parser = parse_recipients)]
        addresses: Option<Vec<(Address<NetworkUnchecked>, u64)>>,
        /// Silent payment code from which you want to derive the script pub key
        #[clap(long = "to-sp", value_parser = parse_sp_recipients)]
        sp_codes: Option<Vec<(SilentPaymentCode, u64)>>,
        /// Debug print the PSBT
        #[clap(long, short)]
        debug: bool,
        #[clap(long, short, default_value = "10")]
        fee_rate: u64,
        /// OP_RETURN
        #[clap(long = "data")]
        data: Option<String>,
        /// descriptor
        #[clap(required = true, last = true)]
        descriptor: Option<String>,
    },
    Balance,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let db_path = if let Ok(db_path) = env::var("DB_PATH") {
        db_path
    } else {
        ".bdk_example_silentpayments.db".to_string()
    };

    let Init {
        args,
        mut wallet,
        db,
    } = match init_or_load(DB_MAGIC, &db_path)? {
        Some(init) => init,
        None => return Ok(()),
    };

    match args.command {
        Commands::DeriveSpForTx {
            rpc_args,
            txid: maybe_txid,
            tx_hex: maybe_tx_hex,
            order,
            label: maybe_label,
        } => {
            let rpc_client = rpc_args.new_client()?;

            let tx = if let Some(tx_hex) = maybe_tx_hex {
                let tx_bytes = Vec::<u8>::from_hex(&tx_hex)?;
                let tx =
                    Transaction::consensus_decode_from_finite_reader(&mut tx_bytes.as_slice())?;
                tx
            } else if let Some(txid) = maybe_txid {
                rpc_client.get_raw_transaction(&txid, None).unwrap()
            } else {
                bail!("Should provide a txid to request tx or the serialized tx")
            };

            let partial_secret = get_partial_secret(&rpc_client, &tx).expect("will fix later");
            let ecdh_shared_secret =
                compute_shared_secret(wallet.indexer().scan_sk(), &partial_secret);
            let maybe_label =
                maybe_label.and_then(|label| wallet.indexer().index().num_to_label.get(&label));
            let spk = get_silentpayment_script_pubkey(
                wallet.indexer().spend_pk(),
                &ecdh_shared_secret,
                order,
                maybe_label,
            );
            let mut obj = serde_json::Map::new();
            obj.insert("txid".to_string(), json!(tx.compute_txid().to_string()));
            obj.insert("script_pubkey".to_string(), json!(spk.to_string()));
            obj.insert("script_pubkey_hex".to_string(), json!(spk.to_hex_string()));
            obj.insert(
                "partial_secret".to_string(),
                json!(partial_secret.to_string()),
            );
            obj.insert(
                "ecdh_shared_secret".to_string(),
                json!(ecdh_shared_secret.to_string()),
            );
            obj.insert("order".to_string(), json!(order.to_string()));
            if let Some(label) = maybe_label {
                obj.insert(
                    "label".to_string(),
                    json!(label.serialize().as_hex().to_string()),
                );
            };
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        Commands::Code { label } => {
            let mut obj = serde_json::Map::new();
            let maybe_address = if let Some(num) = label {
                wallet.get_labelled_address(num).ok()
            } else {
                Some(wallet.get_address())
            };
            if let Some(address) = maybe_address {
                obj.insert(
                    "silent_payment_code".to_string(),
                    json!(address.to_string()),
                );
                println!("{}", serde_json::to_string_pretty(&obj)?);
            }
        }
        Commands::ScanCbf { tweak_server_url } => {
            async fn trace(
                mut log_rx: kyoto::Receiver<String>,
                mut info_rx: kyoto::Receiver<Info>,
                mut warn_rx: UnboundedReceiver<Warning>,
            ) {
                loop {
                    select! {
                        log = log_rx.recv() => {
                            if let Some(log) = log {
                                tracing::info!("{log}");
                            }
                        }
                        info = info_rx.recv() => {
                            if let Some(info) = info {
                                tracing::info!("{info}");
                            }
                        }
                        warn = warn_rx.recv() => {
                            if let Some(warn) = warn {
                                tracing::warn!("{warn}");
                            }
                        }
                    }
                }
            }

            tracing::info!("Wallet main SP address: {}", wallet.get_address());

            let sync_height = if wallet.birthday <= wallet.chain().tip().height() {
                wallet.chain().tip().height()
            } else {
                wallet.birthday
            };

            tracing::info!("Synchronizing from block {sync_height}");

            // Set up the light client
            let checkpoint =
                HeaderCheckpoint::closest_checkpoint_below_height(sync_height, wallet.network());
            let peer_1 = IpAddr::V4(Ipv4Addr::new(95, 217, 198, 121));
            let peer_2 = TrustedPeer::new(
                AddrV2::Ipv4(Ipv4Addr::new(23, 137, 57, 100)),
                None,
                ServiceFlags::P2P_V2,
            );
            let builder = NodeBuilder::new(wallet.network());
            let (node, client) = builder
                .after_checkpoint(checkpoint)
                .add_peers(vec![(peer_1, None).into(), peer_2])
                .required_peers(2)
                .build()
                .unwrap();
            let (changes_tx, changes_rx) = tokio::sync::mpsc::unbounded_channel::<FilterEvent>();
            let (matches_tx, mut matches_rx) = tokio::sync::mpsc::unbounded_channel::<TweakEvent>();

            let KyotoClient {
                requester,
                log_rx,
                info_rx,
                warn_rx,
                event_rx,
            } = client;

            let (mut blindbit_subscriber, db_buffer) = BlindbitSubscriber::new(
                wallet.indexer().clone(),
                tweak_server_url,
                wallet.network(),
                changes_rx,
                matches_tx,
            )
            .unwrap();

            let mut filter_subscriber =
                FilterSubscriber::new(db_buffer, event_rx, changes_tx, sync_height);

            tracing::info!("Starting the node...");
            tokio::task::spawn(async move {
                if let Err(e) = node.run().await {
                    return Err(e);
                }
                Ok(())
            });

            tracing::info!("Starting blindbit subscriber...");
            tokio::task::spawn(async move { blindbit_subscriber.run().await });

            tracing::info!("Initializing log loop...");
            tokio::task::spawn(async move { trace(log_rx, info_rx, warn_rx).await });

            tracing::info!("Starting filter subscriber...");
            tokio::task::spawn(async move { filter_subscriber.run().await });

            tracing::info!("Synchronizing wallet...");
            loop {
                if let Some(tweak_event) = matches_rx.recv().await {
                    match tweak_event {
                        TweakEvent::Matches((hash, spks_tweak_map)) => {
                            tracing::info!("Checking matches...");
                            if let Ok(rrx) = requester.request_block(hash) {
                                if let Ok(Ok(IndexedBlock { height, ref block })) = rrx.await {
                                    let checkpoint =
                                        wallet.chain().tip().insert(BlockId { height, hash });
                                    wallet.update_chain(checkpoint);

                                    let mut partial_secrets = HashMap::<Txid, PublicKey>::new();
                                    for tx in block.txdata.iter() {
                                        let spks = tx
                                            .output
                                            .iter()
                                            .filter(|txout| txout.script_pubkey.is_p2tr())
                                            .map(|txout| {
                                                txout
                                                    .script_pubkey
                                                    .to_bytes()
                                                    .try_into()
                                                    .expect("p2tr script, should succeed")
                                            })
                                            .collect::<HashSet<[u8; 34]>>();
                                        if let Some(tweak) =
                                            spks.iter().find_map(|spk| spks_tweak_map.get(spk))
                                        {
                                            partial_secrets.insert(tx.compute_txid(), *tweak);
                                        }
                                    }

                                    if !partial_secrets.is_empty() {
                                        tracing::info!("Block {hash} is relevant, indexing.");
                                        wallet.apply_block_relevant(block, partial_secrets, height);
                                    }
                                }
                            }
                        }
                        TweakEvent::Synced(new_tip) => {
                            tracing::info!("Updating to last checkpoint");
                            let checkpoint = wallet.chain().tip().insert(new_tip);
                            wallet.update_chain(checkpoint);
                            tracing::info!("Shutting Down");
                            requester.shutdown().unwrap();
                            break;
                        }
                    }
                }
            }
        }
        Commands::ScanRpc { rpc_args } => {
            let rpc_client = rpc_args.new_client()?;
            let mut emitter = Emitter::new(
                &rpc_client,
                wallet.chain().tip(),
                0,
                NO_EXPECTED_MEMPOOL_TXIDS,
            );

            let start = Instant::now();
            let mut last_db_commit = Instant::now();
            let mut last_print = Instant::now();
            let mut never_printed = true;

            while let Some(emission) = emitter.next_block()? {
                let height = emission.block_height();
                wallet.update_chain(emission.checkpoint);

                let block = &emission.block;
                let Block { ref txdata, .. } = block;

                let partial_secrets: HashMap<Txid, PublicKey> = txdata
                    .iter()
                    .skip(1)
                    .filter_map(|tx| {
                        get_partial_secret(&rpc_client, tx)
                            .map(|partial_secret| (tx.compute_txid(), partial_secret))
                    })
                    .collect();

                wallet.apply_block_relevant(block, partial_secrets, height);

                // commit staged db changes in intervals
                if last_db_commit.elapsed() >= DB_COMMIT_DELAY {
                    let db = &mut *db.lock().unwrap();
                    last_db_commit = Instant::now();
                    if let Some(changeset) = wallet.take_staged() {
                        db.append(&changeset)?;
                    }
                    println!(
                        "[{:>10}s] committed to db (took {}s)",
                        start.elapsed().as_secs_f32(),
                        last_db_commit.elapsed().as_secs_f32()
                    );
                }

                // print synced-to height and current balance in intervals
                if last_print.elapsed() >= STDOUT_PRINT_DELAY {
                    last_print = Instant::now();
                    let balance = wallet.balance();
                    let tip = wallet.chain().tip();
                    println!(
                        "[{:>10}s] synced to {} @ {} | total: {}",
                        start.elapsed().as_secs_f32(),
                        tip.hash(),
                        tip.height(),
                        balance.total()
                    );
                    never_printed = false;
                }
            }

            let db = &mut *db.lock().unwrap();
            if let Some(changeset) = wallet.take_staged() {
                db.append(&changeset)?;
            }
            println!(
                "[{:>10}s] committed to db (took {}s)",
                start.elapsed().as_secs_f32(),
                last_db_commit.elapsed().as_secs_f32()
            );

            if never_printed {
                let balance = wallet.balance();
                let tip = wallet.chain().tip();
                println!(
                    "[{:>10}s] synced to {} @ {} | total: {}",
                    start.elapsed().as_secs_f32(),
                    tip.hash(),
                    tip.height(),
                    balance.total()
                );
            }
        }
        Commands::Balance => {
            fn print_balances<'a>(
                title_str: &'a str,
                items: impl IntoIterator<Item = (&'a str, Amount)>,
            ) -> anyhow::Result<()> {
                let mut obj = serde_json::Map::new();
                let mut sub_obj = serde_json::Map::new();
                for (name, amount) in items.into_iter() {
                    sub_obj.insert(name.to_string(), json!(amount.to_sat()));
                }
                obj.insert(title_str.to_string(), json!(sub_obj));
                println!("{}", serde_json::to_string_pretty(&obj)?);
                Ok(())
            }

            let balance = wallet.balance();

            let confirmed_total = balance.confirmed + balance.immature;
            let unconfirmed_total = balance.untrusted_pending + balance.trusted_pending;

            print_balances(
                "confirmed",
                [
                    ("total", confirmed_total),
                    ("spendable", balance.confirmed),
                    ("immature", balance.immature),
                ],
            )?;
            print_balances(
                "unconfirmed",
                [
                    ("total", unconfirmed_total),
                    ("trusted", balance.trusted_pending),
                    ("untrusted", balance.untrusted_pending),
                ],
            )?;
        }
        Commands::NewTx {
            addresses: maybe_addresses,
            sp_codes: maybe_sp_codes,
            debug: _,
            descriptor,
            fee_rate,
            data,
        } => {
            let secp = Secp256k1::new();
            let mut outputs = vec![];
            if let Some(addresses) = maybe_addresses {
                for (address, value) in addresses {
                    let checked_address = address
                        .require_network(wallet.network())
                        .expect("will fix later");
                    outputs.push(Output::with_script(
                        checked_address.script_pubkey(),
                        Amount::from_sat(value),
                    ));
                }
            }

            let mut sp_recipients: Vec<SilentPaymentCode> = vec![wallet.get_change_address()];
            if let Some(sp_codes) = maybe_sp_codes {
                for (sp_code, value) in sp_codes {
                    if sp_code.network != wallet.network() {
                        bail!("");
                    }
                    let placeholder_script = sp_code.get_placeholder_p2tr_spk();
                    outputs.push(Output::with_script(
                        placeholder_script,
                        Amount::from_sat(value),
                    ));
                    sp_recipients.push(sp_code);
                }
            }

            if outputs.is_empty() {
                return Ok(());
            }

            if let Some(string_data) = data {
                let bytes = PushBytesBuf::try_from(string_data.as_bytes().to_vec()).unwrap();
                let script = ScriptBuf::new_op_return(bytes);
                outputs.push(Output::with_script(script, Amount::from_sat(0)));
            }

            let (tip_height, tip_time) = wallet.tip_info();
            let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);
            let selection = wallet
                .all_candidates()
                .regroup(group_by_spk())
                .filter(filter_unspendable_now(tip_height, tip_time))
                .into_selection(
                    selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
                    SelectorParams::new(
                        FeeRate::from_sat_per_vb_unchecked(fee_rate),
                        outputs,
                        bdk_tx::ChangeDescriptor::Manual {
                            script_pubkey: wallet.get_change_address().get_placeholder_p2tr_spk(),
                            max_weight_to_satisfy_wu: SpWallet::DEFAULT_SPENDING_WEIGHT,
                        },
                        bdk_tx::ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
                    ),
                )?;

            let mut psbt = selection.create_psbt(PsbtParams {
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })?;

            let finalizer = selection.clone().into_finalizer();
            let descriptor = descriptor.expect("already checked is some");
            let spend_sk = get_spend_sk(&descriptor, wallet.network());

            for i in 0..psbt.inputs.len() {
                let tweak = wallet
                    .indexer()
                    .index()
                    .get_by_script(&psbt.inputs[i].witness_utxo.clone().unwrap().script_pubkey)
                    .unwrap();
                add_sp_data_to_input(
                    &mut psbt,
                    i,
                    *wallet.indexer().spend_pk(),
                    Scalar::from(*tweak),
                );
            }

            let spend_prv = PrivateKey::new(spend_sk, wallet.network());
            let spend_pub = bitcoin::PublicKey::new(*wallet.indexer().spend_pk());
            assert_eq!(spend_prv.public_key(&secp), spend_pub);
            let mut spend_keys = HashMap::<bitcoin::PublicKey, PrivateKey>::new();
            spend_keys.insert(spend_pub, spend_prv);

            // replace outputs by real final silentpayment script pubkeys
            derive_sp(&mut psbt, &spend_keys, &sp_recipients, &secp)?;

            sign_sp(&mut psbt, &spend_keys, &secp);

            let _res = finalizer.finalize(&mut psbt);

            let tx = psbt.extract_tx()?;

            let mut obj = serde_json::Map::new();
            obj.insert(
                "tx".to_string(),
                json!(bitcoin::consensus::encode::serialize_hex(&tx)),
            );
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        Commands::Create { .. } => {
            unreachable!("already handled by init_or_load")
        }
    };

    let db = &mut *db.lock().unwrap();
    if let Some(changeset) = wallet.take_staged() {
        db.append(&changeset)?;
    }

    Ok(())
}

/// The initial state returned by [`init_or_load`].
pub struct Init {
    /// CLI args
    pub args: SpArgs,
    /// SpWallet
    pub wallet: SpWallet,
    /// Store
    pub db: Mutex<Store<ChangeSet>>,
}

pub fn init_or_load(db_magic: &[u8], db_path: &str) -> anyhow::Result<Option<Init>> {
    let args = SpArgs::parse();

    match args.command {
        Commands::Create {
            network,
            birthday,
            genesis_hash,
        } => {
            let secp = Secp256k1::new();
            let mut seed = [0x00; 32];
            rand::rng().fill_bytes(&mut seed);

            let m = bip32::Xpriv::new_master(network, &seed)?;
            let fp = m.fingerprint(&secp);
            let tr_xprv = format!("tr([{fp}]{m})");

            let mut obj = serde_json::Map::new();
            obj.insert("tr_xprv".to_string(), json!(tr_xprv.to_string()));

            println!("{}", serde_json::to_string_pretty(&obj)?);

            let block_hash = if let Some(hash) = genesis_hash {
                hash
            } else {
                let genesis_block = bitcoin::constants::genesis_block(network);
                genesis_block.block_hash()
            };

            let wallet = SpWallet::new(birthday, block_hash, &tr_xprv, network).unwrap();
            let mut db = Store::<ChangeSet>::create(db_magic, db_path)?;
            if let Some(stage) = wallet.staged() {
                db.append(stage).unwrap();
            }
            Ok(None)
        }
        _ => {
            let (db, changeset) =
                Store::<ChangeSet>::load(db_magic, db_path).context("could not open file store")?;

            if let Some(stage) = changeset {
                let wallet = SpWallet::try_from(stage).unwrap();
                Ok(Some(Init {
                    args,
                    wallet,
                    db: db.into(),
                }))
            } else {
                bail!("")
            }
        }
    }
}

fn get_partial_secret(
    client: &impl RpcApi,
    tx: &Transaction,
) -> Option<bitcoin::secp256k1::PublicKey> {
    let mut prevouts = <Vec<TxOut>>::new();
    let outpoint_refs = tx.input.iter().map(|x| x.previous_output);
    for OutPoint { txid, vout } in outpoint_refs {
        let prev_tx = client
            .get_raw_transaction_info(&txid, None)
            .ok()
            .and_then(|tx| tx.transaction().ok())?;
        let prevout = prev_tx.tx_out(vout as usize).ok()?.clone();
        prevouts.push(prevout);
    }
    compute_tweak_data(tx, &prevouts).ok()
}
