use bdk_chain::{
    bitcoin::{
        TxIn,
        bip32,
        key::{Keypair, Parity},
        secp256k1::{self, Message, Secp256k1, SecretKey},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature,
        transaction, Address, Amount, Network, OutPoint, PrivateKey, Sequence, Witness,
    },
    miniscript::{descriptor::DescriptorSecretKey, Descriptor, DescriptorPublicKey},
};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use std::fmt;
use std::{collections::HashMap, error::Error};

use example_rust_silentpayments::{Scanner, SilentPaymentAddress, XprivSilentPaymentSender};

#[derive(
    Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
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

fn get_sp_keys() -> (SilentPaymentAddress, SecretKey, SecretKey) {
    let secp = secp256k1::Secp256k1::new();
    let silent_payment_string: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";
    let spend_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif("cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11")
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let scan_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif("cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24")
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    let sp_code = SilentPaymentAddress {
        version: 0,
        scan: scan_privkey.public_key(&secp),
        spend: spend_privkey.public_key(&secp),
        network: Network::Regtest,
    };

    assert_eq!(format!("{}", sp_code), silent_payment_string);

    (sp_code, scan_privkey, spend_privkey)
}

fn main() -> Result<(), Box<dyn Error>> {
    let env = TestEnv::new()?;
    let rpc_client = env.rpc_client();
    let (txid, block_hash, txout) = fund_wallet_and_send_silent_payment(rpc_client).unwrap();
    let tx_to_scan = rpc_client
        .get_raw_transaction(&txid, Some(&block_hash))
        .unwrap();

    let (sp_code, scan_sk, spend_sk) = get_sp_keys();

    let scanner = Scanner::new(scan_sk, sp_code.spend, <HashMap<_, _>>::new());

    for sp_output in scanner.scan_tx(&tx_to_scan, &[txout]) {
        let output_sk = spend_sk.add_tweak(&sp_output.tweak).unwrap();
        // Check the output is spendable
        assert_eq!(
            output_sk.x_only_public_key(&Secp256k1::new()).0,
            sp_output.public_key
        );

        println!("output found and spendable!");
    }

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
    let network = Network::Regtest;
    let secp = Secp256k1::new();
    let (descriptor, keymap) =
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&secp, EXTERNAL_DESCRIPTOR)?;

    let spk = descriptor.at_derivation_index(0).unwrap().script_pubkey();
    let addr = Address::from_script(spk.as_script(), network)?;

    let (_addr_pubkey, addr_privkey) = keymap.iter().collect::<Vec<_>>()[0];
    let addr_privkey = if let DescriptorSecretKey::XPrv(privkey) = addr_privkey {
        privkey
    } else {
        panic!("just break");
    };

    let _ = rpc_client.generate_to_address(101, &addr)?;
    let txid = rpc_client
        .send_to_address(
            &addr,
            Amount::from_int_btc(21),
            None,
            None,
            Some(false),
            Some(false),
            Some(1),
            None,
        )
        .unwrap();
    let addr_block_hash = rpc_client.generate_to_address(1, &addr).unwrap()[0];

    let funding_block = rpc_client.get_block(&addr_block_hash).unwrap();
    assert!(funding_block
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid));

    let tx = rpc_client
        .get_raw_transaction(&txid, Some(&addr_block_hash))
        .unwrap();

    println!("silent payment input txid: {}", txid);
    let (txout, output_idx) = tx
        .output
        .iter()
        .zip(0_u32..)
        .find(|(x, _idx)| x.value == Amount::from_int_btc(21))
        .unwrap();

    let master_privkey = addr_privkey.xkey;

    let sp_sender = XprivSilentPaymentSender::new(master_privkey);

    let privkey_deriv_path = addr_privkey
        .derivation_path
        .child(bip32::ChildNumber::Normal { index: 0 });

    let bip32_privkey = master_privkey
        .derive_priv(&secp, &privkey_deriv_path)
        .unwrap();

    let (x_only_internal, parity) = bip32_privkey.private_key.x_only_public_key(&secp);

    let mut internal_privkey = bip32_privkey.private_key;
    if let Parity::Odd = parity {
        internal_privkey = internal_privkey.negate();
    }

    let tap_tweak = bdk_chain::bitcoin::TapTweakHash::from_key_and_tweak(x_only_internal, None);
    let (x_only_external, parity) = x_only_internal
        .add_tweak(&secp, &tap_tweak.to_scalar())
        .unwrap();
    assert!(addr.is_related_to_xonly_pubkey(&x_only_external));
    let mut external_privkey = internal_privkey.add_tweak(&tap_tweak.to_scalar()).unwrap();
    if let Parity::Odd = parity {
        external_privkey = external_privkey.negate();
    }

    let keypair_from_external = Keypair::from_secret_key(&secp, &external_privkey);
    let selected_outpoint = OutPoint {
        txid,
        vout: output_idx,
    };

    let (sp_code, ..) = get_sp_keys();

    let txouts = sp_sender.send_to(
        &[(selected_outpoint, privkey_deriv_path)],
        &[(sp_code, txout.value - Amount::from_sat(1000))],
    );

    let silent_payment_txin = TxIn {
        previous_output: selected_outpoint,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    };

    let mut unsigned_tx = transaction::Transaction {
        version: transaction::Version::TWO,
        lock_time: bdk_chain::bitcoin::absolute::LockTime::from_height(0).unwrap(),
        input: vec![silent_payment_txin],
        output: txouts,
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![txout.clone()];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
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

    Ok((txid_sp, *sp_block_hash, txout.clone()))
}
