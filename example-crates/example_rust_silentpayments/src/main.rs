use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use bdk_bitcoind_rpc::Emitter;

use bdk_chain::{
    bitcoin::{
        bip32,
        key::{Keypair, Parity, TapTweak, TweakedKeypair, UntweakedPublicKey},
        secp256k1::{rand, Message, Secp256k1, SecretKey, Signing, Verification},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature,
        transaction, Address, Amount, Network, PrivateKey, Psbt, Sequence,
        Witness
    },
    indexer::keychain_txout::KeychainTxOutIndex,
    miniscript::{
        bitcoin::secp256k1 as miniscript_secp, descriptor::DescriptorSecretKey, plan::Assets,
        psbt::PsbtExt, Descriptor, DescriptorPublicKey,
    },
};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};

use silentpayments::secp256k1 as sp_secp;
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input,
};
use silentpayments::utils::sending::calculate_partial_secret;
use silentpayments::{
    receiving::{Label, Receiver},
    sending::generate_recipient_pubkeys,
};

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/////////////////////// Sending wallet PREAMBLE ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#[derive(
    Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, serde::Deserialize, serde::Serialize,
)]
pub enum Keychain {
    External,
    Internal,
}

impl fmt::Display for Keychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keychain::External => write!(f, "external"),
            Keychain::Internal => write!(f, "internal"),
        }
    }
}

const EXTERNAL_DESCRIPTOR: &str = "tr([3794bb41]tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq/86'/1'/0'/0/*)#dg6yxkuh";
const INTERNAL_DESCRIPTOR: &str = "tr([3794bb41]tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq/86'/1'/0'/1/*)#uul9mrv0";

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////// Silent payment wallet ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

fn get_sp_keys() -> (Receiver, sp_secp::SecretKey, sp_secp::SecretKey) {
    let sp_secp_1 = sp_secp::Secp256k1::new();
    let silent_payment_string: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";
    let spend_privkey = sp_secp::SecretKey::from_slice(
        &PrivateKey::from_wif("cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11")
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let scan_privkey = sp_secp::SecretKey::from_slice(
        &PrivateKey::from_wif("cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24")
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    // Create a change label for the wallet
    let change_label = Label::new(spend_privkey, 0);

    // Create a new Receiver object with the private and public keys, along with the change label
    let receiver = Receiver::new(
        0,
        scan_privkey.public_key(&sp_secp_1),
        spend_privkey.public_key(&sp_secp_1),
        change_label,
        silentpayments::Network::Regtest,
    )
    .unwrap();

    println!("Receiver address: {}", receiver.get_receiving_address());
    assert_eq!(
        format!("{}", receiver.get_receiving_address()),
        silent_payment_string
    );

    (receiver, spend_privkey, scan_privkey)
}

fn main() -> Result<(), Box<dyn Error>> {
    let env = TestEnv::new()?;
    let rpc_client = env.rpc_client();
    let (txid, block_hash, txout) = fund_wallet_and_send_silent_payment(rpc_client).unwrap();
    let tx_to_scan = rpc_client
        .get_raw_transaction(&txid, Some(&block_hash))
        .unwrap();
    let input = tx_to_scan.input.first().unwrap().previous_output;
    scan_block_for_silent_payment_tx(txout, tx_to_scan);
    Ok(())
}

fn scan_block_for_silent_payment_tx(
    prevout: transaction::TxOut,
    tx: transaction::Transaction,
) -> Result<(), Box<dyn Error>> {
    let (receiver, spend_privkey, scan_privkey) = get_sp_keys();

    let txin = tx.input.first().unwrap();
    let txin_outpoint = txin.previous_output;
    println!("funding outpoint: {}", txin_outpoint);
    let script_sig = txin.script_sig.clone();
    let txwitness = txin.witness.clone();
    let script_pubkey = prevout.script_pubkey.clone();

    let txin_pubkey = get_pubkey_from_input(
        script_sig.as_bytes(),
        &txwitness.to_vec(),
        script_pubkey.as_bytes(),
    )
    .unwrap()
    .unwrap();
    println!("sp input pubkey: {}", txin_pubkey);
    let pubkeys = vec![&txin_pubkey];

    let outpoint_data = vec![(txin_outpoint.txid.to_string(), txin_outpoint.vout)];
    let tweak_data = calculate_tweak_data(&pubkeys, &outpoint_data).unwrap();
    let ecdh_secret = calculate_ecdh_shared_secret(&tweak_data, &scan_privkey);

    let output_pubkey = tx
        .output
        .iter()
        .filter_map(|txout| {
            if let Ok(res) =
                sp_secp::XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
            {
                Some(res)
            } else {
                None
            }
        })
        .collect();
    let scanned_outputs = receiver
        .scan_transaction(&ecdh_secret, output_pubkey)
        .unwrap();

    dbg!(scanned_outputs);

    Ok(())
}

fn fund_wallet_and_send_silent_payment(
    rpc_client: &impl RpcApi,
) -> Result<
    (
        transaction::Txid,
        bdk_chain::bitcoin::BlockHash,
        transaction::TxOut,
    ),
    Box<dyn Error>,
> {
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    /////////////////////////// Fund sending wallet ///////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    let network = Network::Regtest;
    let secp = miniscript_secp::Secp256k1::new();
    let (descriptor, keymap) =
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&secp, EXTERNAL_DESCRIPTOR)?;
    let (internal_descriptor, internal_keymap) =
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&secp, INTERNAL_DESCRIPTOR)?;

    let mut index = KeychainTxOutIndex::default();
    let _ = index.insert_descriptor(Keychain::External, descriptor.clone())?;

    let _ = index.insert_descriptor(Keychain::Internal, internal_descriptor.clone())?;

    let ((spk_i, spk), _) =
        KeychainTxOutIndex::reveal_next_spk(&mut index, Keychain::External).expect("Must exist");

    let addr = Address::from_script(spk.as_script(), network)?;

    let ((spk_i_1, spk_1), _) =
        KeychainTxOutIndex::reveal_next_spk(&mut index, Keychain::External).expect("Must exist");

    let addr_1 = Address::from_script(spk_1.as_script(), network).unwrap();

    assert_ne!(addr, addr_1);

    let (addr_1_pubkey, addr_1_privkey) = keymap.iter().collect::<Vec<_>>()[0];
    let addr_1_privkey = if let DescriptorSecretKey::XPrv(privkey) = addr_1_privkey {
        privkey
    } else {
        panic!("just break");
    };

    ///////////////////////////////////////////////////////////////////////////////
    ////////////////////// Send mining rewards to wallet //////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    let _ = rpc_client.generate_to_address(101, &addr)?;
    ///////////////////////////////////////////////////////////////////////////////
    ///////////// Create UTxO not coming from coinabse transaction ////////////////
    ///////////////////////////////////////////////////////////////////////////////
    let txid_21 = rpc_client
        .send_to_address(
            &addr_1,
            Amount::from_int_btc(21),
            None,
            None,
            Some(false),
            Some(false),
            Some(1),
            None,
        )
        .unwrap();
    let addr_1_block_hash = rpc_client.generate_to_address(1, &addr).unwrap()[0];

    let block_21 = rpc_client.get_block(&addr_1_block_hash).unwrap();
    assert!(block_21
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid_21));

    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    /////////////////////////// Prepare sender data ///////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    let tx_21 = rpc_client
        .get_raw_transaction(&txid_21, Some(&addr_1_block_hash))
        .unwrap();

    dbg!("silent payment input txid:", txid_21);
    let outputs = tx_21
        .output
        .iter()
        .zip(0_u32..)
        .filter(|(x, idx)| x.value == Amount::from_int_btc(21))
        .collect::<Vec<_>>();
    let (txout, output_idx) = outputs[0];

    let master_privkey = addr_1_privkey.xkey;
    let privkey_deriv_path = addr_1_privkey
        .derivation_path
        .child(bip32::ChildNumber::Normal { index: spk_i_1 });

    let miniscript = miniscript_secp::Secp256k1::new();
    let bip32_privkey = master_privkey
        .derive_priv(&miniscript, &privkey_deriv_path)
        .unwrap();

    let (x_only_internal, parity) = bip32_privkey
        .private_key
        .x_only_public_key(&Secp256k1::new());

    let mut internal_privkey = bip32_privkey.private_key;
    if let Parity::Odd = parity {
        internal_privkey = internal_privkey.negate();
    }

    let tap_tweak = bdk_chain::bitcoin::TapTweakHash::from_key_and_tweak(x_only_internal, None);
    let (x_only_external, parity) = x_only_internal
        .add_tweak(&Secp256k1::new(), &tap_tweak.to_scalar())
        .unwrap();
    let mut external_privkey = internal_privkey.add_tweak(&tap_tweak.to_scalar()).unwrap();
    if let Parity::Odd = parity {
        external_privkey = external_privkey.negate();
    }

    let keypair_from_external = Keypair::from_secret_key(&Secp256k1::new(), &external_privkey);

    // We know for sure the original descriptor was a taproot one
    let input_private_keys = vec![(
        sp_secp::SecretKey::from_slice(&external_privkey.secret_bytes()).unwrap(),
        true,
    )];

    // Assuming the 21 UTxO is the first one in the list
    let outpoints = vec![(txid_21.to_string(), output_idx)];

    let input_hash = calculate_partial_secret(&input_private_keys, &outpoints).unwrap();

    let mut assets = Assets::new();
    if let Descriptor::Tr(ref tr) = descriptor {
        assets = assets.add(tr.internal_key().clone());
    }

    let plan = descriptor
        .at_derivation_index(spk_i_1)
        .unwrap()
        .plan(&assets)
        .ok()
        .unwrap();

    let silent_payment_txin = transaction::TxIn {
        previous_output: transaction::OutPoint {
            txid: txid_21,
            vout: output_idx,
        },
        sequence: plan
            .relative_timelock
            .map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, Sequence::from),
        ..Default::default()
    };

    // Iterate through each input of the transaction and assert if it contains an eligible pubkey

    ///////////////////////////////////////////////////////////////////////////////
    /////////////////////////// Get silent payment data ///////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    let (receiver, _, _) = get_sp_keys();

    ///////////////////////////////////////////////////////////////////////////////
    //////////////////////// Create silent payment output /////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    let sp_address_sp_output_map =
        generate_recipient_pubkeys(vec![receiver.get_receiving_address()], input_hash).unwrap();

    let sp_x_pubkey = sp_address_sp_output_map
        .get(&receiver.get_receiving_address())
        .unwrap()[0]
        .serialize();
    let bitcoin_sp_x_pubkey = bdk_chain::bitcoin::XOnlyPublicKey::from_slice(&sp_x_pubkey).unwrap();
    let sp_final_address = Address::p2tr(
        &Secp256k1::new(),
        bitcoin_sp_x_pubkey,
        None,
        bdk_chain::bitcoin::Network::Regtest,
    );
    let sp_output = transaction::TxOut {
        value: txout.value - Amount::from_sat(1000),
        script_pubkey: sp_final_address.into(),
    };

    ///////////////////////////////////////////////////////////////////////////////
    ////////////////////////////// Create Tx /////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    let mut unsigned_tx = transaction::Transaction {
        version: transaction::Version::TWO,
        lock_time: bdk_chain::bitcoin::absolute::LockTime::from_height(0).unwrap(),
        input: vec![silent_payment_txin],
        output: vec![sp_output],
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![txout.clone()];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    //let tweaked: TweakedKeypair = keypair_from_external.tap_tweak(&secp, None);
    let msg = Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &keypair_from_external);

    // Update the witness stack.
    let signature = Signature {
        signature,
        sighash_type,
    };
    *sighasher.witness_mut(0).unwrap() = Witness::p2tr_key_spend(&signature);

    // Get the signed transaction.
    let tx = sighasher.transaction();

    //  let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    //  let psbt_input = &mut psbt.inputs[0];
    //  plan.update_psbt_input(psbt_input);
    //  psbt_input.witness_utxo = Some(txout.clone());

    //  let sign_res = psbt
    //      .sign(&master_privkey, &Secp256k1::new())
    //      .unwrap();

    //  assert!(!sign_res.is_empty());

    //  psbt.finalize_mut(&Secp256k1::new())
    //      .unwrap();

    //  let tx = psbt.extract_tx().unwrap();

    let txid_sp = rpc_client.send_raw_transaction(tx).unwrap();

    println!("txid silent payment: {}", txid_sp);

    let block_hashes = rpc_client.generate_to_address(1, &addr).unwrap();
    let sp_block_hash = block_hashes.first().unwrap();
    let block_sp = rpc_client.get_block(sp_block_hash).unwrap();
    assert!(block_sp
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid_sp));

    println!("silent payment block hash: {}", sp_block_hash);

    // Create and fund sending wallet
    Ok((txid_sp, *sp_block_hash, txout.clone()))
}
