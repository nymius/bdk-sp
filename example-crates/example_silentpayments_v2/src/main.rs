use anyhow::{self, bail, Context};
use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client, RpcApi},
    Emitter, NO_EXPECTED_MEMPOOL_TXIDS,
};
use bdk_file_store::Store;
use bdk_sp::{
    bitcoin::{
        self, address::NetworkUnchecked, bip32, key::Secp256k1, secp256k1::PublicKey, Address,
        Amount, Block, FeeRate, Network, OutPoint, Sequence, Transaction, TxOut, Txid,
    },
    encoding::SilentPaymentCode,
    receive::compute_tweak_data,
    send::psbt::derive_sp,
};
use bdk_sp_wallet::{
    sp_signer::{get_spend_sk, populate_sp_keymap},
    ChangeSet, SpWallet,
};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, Output, PsbtParams,
    SelectorParams,
};
use clap::{self, Args, Parser, Subcommand};
use rand::RngCore;
use serde_json::json;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

const DB_MAGIC: &[u8] = b"bdk_example_silentpayments";
const DB_PATH: &str = ".bdk_example_silentpayments.db";

/// Delay for printing status to stdout.
const STDOUT_PRINT_DELAY: Duration = Duration::from_secs(6);
/// Delay for committing to persistence.
const DB_COMMIT_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct KeyValuePair<T>(pub T, pub u64);

impl FromStr for KeyValuePair<Address<NetworkUnchecked>> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('=').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid format '{}'. Expected 'key=value'", s));
        }

        let value_0 = parts[0].trim();
        let address = Address::<NetworkUnchecked>::from_str(value_0)
            .map_err(|_| format!("Invalid address: {}", value_0))?;
        let value = parts[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("Invalid number '{}' for key '{}'", parts[1], value_0))?;

        Ok(KeyValuePair(address, value))
    }
}

impl FromStr for KeyValuePair<SilentPaymentCode> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('=').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid format '{}'. Expected 'key=value'", s));
        }

        let value_0 = parts[0].trim();
        let key = SilentPaymentCode::try_from(value_0)
            .map_err(|_| format!("Invalid silent payment address: {}", value_0))?;
        let value = parts[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("Invalid number '{}' for key '{}'", parts[1], key))?;

        Ok(KeyValuePair(key, value))
    }
}

fn parse_address_value_pairs(s: &str) -> Result<Vec<(Address<NetworkUnchecked>, u64)>, String> {
    s.split(',')
        .map(|pair| KeyValuePair::from_str(pair.trim()).map(|kvp| (kvp.0, kvp.1)))
        .collect()
}

fn parse_sp_code_value_pairs(s: &str) -> Result<Vec<(SilentPaymentCode, u64)>, String> {
    s.split(',')
        .map(|pair| KeyValuePair::from_str(pair.trim()).map(|kvp| (kvp.0, kvp.1)))
        .collect()
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
    Create {
        /// Network
        #[clap(long, short, default_value = "signet")]
        network: Network,
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
    NewPsbt {
        /// Recipient address
        #[clap(value_parser = parse_address_value_pairs)]
        addresses: Option<Vec<(Address<NetworkUnchecked>, u64)>>,
        /// Silent payment code from which you want to derive the script pub key
        #[clap(long = "code", value_parser = parse_sp_code_value_pairs)]
        silent_payment_recipients: Option<Vec<(SilentPaymentCode, u64)>>,
        /// Debug print the PSBT
        #[clap(long, short)]
        debug: bool,
        /// descriptor
        descriptor: Option<String>,
    },
    Balance,
}

fn main() -> anyhow::Result<()> {
    let Init {
        args,
        mut wallet,
        db,
    } = match init_or_load(DB_MAGIC, DB_PATH)? {
        Some(init) => init,
        None => return Ok(()),
    };

    match args.command {
        Commands::Code { label } => {
            let mut obj = serde_json::Map::new();
            let maybe_address = if let Some(num) = label {
                wallet.get_labeled_address(num).ok()
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

                let block = &emission.block;
                let Block { ref txdata, .. } = block;

                let partial_secrets: HashMap<Txid, PublicKey> = txdata
                    .iter()
                    .skip(1)
                    .map(|tx| {
                        (
                            tx.compute_txid(),
                            get_partial_secret(&rpc_client, tx).expect("will fix later"),
                        )
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
        Commands::NewPsbt {
            addresses: maybe_addresses,
            silent_payment_recipients: maybe_sp_codes,
            debug: _,
            descriptor,
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

            let mut recipients: Vec<SilentPaymentCode> = vec![];
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
                    recipients.push(sp_code);
                }
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
                        FeeRate::from_sat_per_vb_unchecked(10),
                        outputs,
                        wallet.get_change_descriptor_placeholder(),
                        bdk_tx::ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
                    ),
                )?;
            let mut psbt = selection.create_psbt(PsbtParams {
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })?;

            let finalizer = selection.clone().into_finalizer();

            if !recipients.is_empty() && descriptor.is_some() {
                let descriptor = descriptor.expect("already checked is some");
                let spend_sk = get_spend_sk(&descriptor, wallet.network());
                let signer =
                    populate_sp_keymap(&spend_sk, wallet.indexer().index(), wallet.network());
                let _ = psbt.sign(&signer, &secp);
                // Finalization is key for sp derivation as the witness provides the knowledge of the type of
                // key used for signing, allowing to know which keys to select for intermediate secret
                // derivation
                let res = finalizer.finalize(&mut psbt);
                assert!(res.is_finalized());

                for (plan_input, psbt_input) in selection.inputs.iter().zip(psbt.inputs.iter_mut())
                {
                    if let Some(plan) = plan_input.plan() {
                        // add bip32 and tap key derivation data
                        plan.update_psbt_input(psbt_input);
                    }
                }

                // replace outputs by real final silentpayment script pubkeys
                derive_sp(&mut psbt, &signer, &recipients, &secp)?;

                for psbt_input in psbt.inputs.iter_mut() {
                    psbt_input.final_script_sig = None;
                    psbt_input.final_script_witness = None;
                }

                let _ = psbt.sign(&signer, &secp);
                let _ = finalizer.finalize(&mut psbt);
            }

            let mut obj = serde_json::Map::new();
            obj.insert("psbt".to_string(), json!(psbt.to_string()));
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        Commands::Create { .. } => {
            unreachable!("already handled by init_or_load")
        }
    };

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
            genesis_hash,
        } => {
            let secp = Secp256k1::new();
            let mut seed = [0x00; 32];
            rand::rng().fill_bytes(&mut seed);

            let m = bip32::Xpriv::new_master(network, &seed)?;
            let fp = m.fingerprint(&secp);
            let tr_desc_str = format!("tr([{fp}]{m})");

            println!("{tr_desc_str}");

            let block_hash = if let Some(hash) = genesis_hash {
                hash
            } else {
                let genesis_block = bitcoin::constants::genesis_block(network);
                genesis_block.block_hash()
            };

            let wallet = SpWallet::new(block_hash, &tr_desc_str, network).unwrap();
            let mut db = Store::<ChangeSet>::create(DB_MAGIC, DB_PATH)?;
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
