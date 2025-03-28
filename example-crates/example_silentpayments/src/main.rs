use bdk_chain::{BlockId, CheckPoint};
use serde_json::json;
use std::collections::HashMap;

use std::env;
use std::str::FromStr;

use anyhow::{self, bail, Context};

use clap::{self, Args, Parser, Subcommand};

use bdk_silentpayments::{
    bitcoin::{
        bip32::DerivationPath,
        secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
        Block, OutPoint, Psbt, TxOut, Txid,
    },
    encoding::SilentPaymentCode,
    receive::{Scanner, SpOutput},
    send::XprivSilentPaymentSender,
};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client, RpcApi},
    Emitter,
};

use miniscript::{descriptor::DescriptorSecretKey, Descriptor};

#[allow(dead_code)]
const SILENT_PAYMENT_SPEND_WIF: &str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";
#[allow(dead_code)]
const SILENT_PAYMENT_SCAN_WIF: &str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
#[allow(dead_code)]
const SILENT_PAYMENT_SPEND_SECRETKEY: &str =
    "6d87b87889341032b6509470233601a722834808def6454450bf42a9af22d263";
const SILENT_PAYMENT_SCAN_SECRETKEY: &str =
    "b700f356a63cbab8da1fb7b3e5cbbfbb4e56d83c8b7271d0bc6f92882f70aa85";
const SILENT_PAYMENT_ENCODED: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

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
    pub command: SilentPaymentCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SilentPaymentCommands {
    /// Replace PSBT single taproot output with a silent payment derived taproot output
    ToSilentPayment {
        /// Silent payment code from which you want to derive the script pub key
        #[clap(default_value = SILENT_PAYMENT_ENCODED)]
        silent_payment_code: String,
        /// The original PSBT you are trying to replace outputs from
        #[clap(long)]
        psbt: String,
        /// Private descriptor you need to get the private keys to create the silent payment script
        /// pubkey
        #[clap(long)]
        descriptor: Option<String>,
        /// Debug print the PSBT
        #[clap(long, short)]
        debug: bool,
    },

    /// Use bitcoind RPC to scan the blockchain looking for silent payment outputs belonging to the
    /// provided silent payment code
    Scan {
        /// The scan key needed to generate the shared secret in combination with tx inputs
        #[clap(long, default_value = SILENT_PAYMENT_SCAN_SECRETKEY)]
        scan_sk: SecretKey,
        /// Silent payment code to get the spend pub key from to derive the full script pubkey
        #[clap(default_value = SILENT_PAYMENT_ENCODED)]
        silent_payment_code: String,
        /// The RPC parameters to communicate with bitcoind RPC
        #[clap(flatten)]
        rpc_args: RpcArgs,
    },
}

fn main() -> anyhow::Result<()> {
    let args = SpArgs::parse();

    match args.command {
        SilentPaymentCommands::ToSilentPayment {
            silent_payment_code,
            psbt,
            descriptor,
            debug,
        } => {
            let mut psbt = Psbt::from_str(psbt.as_str())?;

            let single_external_txout = psbt
                .unsigned_tx
                .output
                .first()
                .expect("send to multiple addresses not implemented yet")
                .clone();

            if !single_external_txout.script_pubkey.is_p2tr() {
                bail!("can only replace p2tr outputs");
            }

            let desc_str = match descriptor {
                Some(s) => s,
                None => env::var("DESCRIPTOR").context("unable to sign")?,
            };

            let secp = Secp256k1::new();
            let (_, keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;
            if keymap.is_empty() {
                bail!("unable to sign")
            }

            let master_privkey = match keymap.iter().next().expect("not empty") {
                (_, DescriptorSecretKey::XPrv(privkey)) => privkey.xkey,
                _ => unimplemented!("multi xkey signer"),
            };

            let sp_sender = XprivSilentPaymentSender::new(master_privkey);

            let silent_payment_code = SilentPaymentCode::try_from(silent_payment_code.as_str())?;

            let mut outputs_and_derivation_paths = <Vec<(OutPoint, DerivationPath)>>::new();
            for (psbt_input, txin) in psbt.inputs.iter().zip(psbt.unsigned_tx.input.clone()) {
                for (fingerprint, path) in psbt_input
                    .bip32_derivation
                    .values()
                    .chain(psbt_input.tap_key_origins.values().map(|x| &x.1))
                {
                    if *fingerprint == master_privkey.fingerprint(&secp) {
                        outputs_and_derivation_paths.push((txin.previous_output, path.clone()));
                        break;
                    }
                }
            }

            let sp_script_pubkeys =
                sp_sender.send_to(&outputs_and_derivation_paths, &[silent_payment_code])?;

            let txout = TxOut {
                value: single_external_txout.value,
                script_pubkey: sp_script_pubkeys
                    .first()
                    .expect("only provided one silent payment code")
                    .clone(),
            };

            psbt.unsigned_tx.output = psbt
                .unsigned_tx
                .output
                .into_iter()
                .map(|x| {
                    if x.script_pubkey == single_external_txout.script_pubkey {
                        txout.clone()
                    } else {
                        x
                    }
                })
                .collect();

            if debug {
                dbg!(psbt);
            } else {
                // print base64 encoded psbt
                let fee = psbt.fee()?.to_sat();
                let mut obj = serde_json::Map::new();
                obj.insert("psbt".to_string(), json!(psbt.to_string()));
                obj.insert("fee".to_string(), json!(fee));
                println!("{}", serde_json::to_string_pretty(&obj)?);
            };
        }
        SilentPaymentCommands::Scan {
            scan_sk,
            silent_payment_code,
            rpc_args,
        } => {
            let silent_payment_code = SilentPaymentCode::try_from(silent_payment_code.as_str())?;

            let rpc_client = rpc_args.new_client()?;
            let chain_tip = CheckPoint::new(BlockId {
                height: 0u32,
                hash: rpc_client.get_block_hash(0)?,
            });
            let label_lookup = HashMap::<PublicKey, (Scalar, u32)>::new();
            let scanner = Scanner::new(scan_sk, silent_payment_code.spend, label_lookup);

            let mut emitter = Emitter::new(&rpc_client, chain_tip, 0);
            let mut found_sp_outputs = <Vec<SpOutput>>::new();

            let mut sp_txs = <Vec<Txid>>::new();
            while let Some(emission) = emitter.next_block()? {
                let _height = emission.block_height();
                let Block {
                    header: _header,
                    txdata,
                } = emission.block;
                for tx in txdata.iter().skip(1) {
                    if !tx.output.iter().any(|x| x.script_pubkey.is_p2tr()) {
                        continue;
                    }
                    let outpoint_refs = tx.input.iter().map(|x| x.previous_output);
                    let mut prevouts = <Vec<TxOut>>::new();
                    for OutPoint { txid, vout } in outpoint_refs {
                        let prev_tx = rpc_client
                            .get_raw_transaction_info(&txid, None)?
                            .transaction()?;
                        let prevout = prev_tx.tx_out(vout as usize)?.clone();
                        prevouts.push(prevout);
                    }
                    let sp_outputs_in_tx = scanner.scan_tx(tx, &prevouts)?;
                    if !sp_outputs_in_tx.is_empty() {
                        sp_txs.push(tx.compute_txid());
                    }
                    found_sp_outputs.extend(sp_outputs_in_tx);
                }
            }
            let mut obj = serde_json::Map::new();
            obj.insert("silent_payments_found".to_string(), json!(&sp_txs));
            println!("{}", serde_json::to_string_pretty(&obj)?);

            let _mempool_txs = emitter.mempool()?;
        }
    };

    Ok(())
}
