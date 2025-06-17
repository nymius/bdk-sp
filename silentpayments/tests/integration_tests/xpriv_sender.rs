use crate::{assert_silentpayment_derivation, get_silentpayment_keys, EXTERNAL_DESCRIPTOR};

use bdk_sp::{
    bitcoin::{
        absolute::LockTime,
        bip32,
        key::{Keypair, Parity, TweakedPublicKey},
        secp256k1::{Message, Secp256k1},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature,
        transaction::Version,
        Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, TapTweakHash,
        Transaction, TxIn, TxOut, Txid, Witness,
    },
    send::bip32::XprivSilentPaymentSender,
};

use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use miniscript::{descriptor::DescriptorSecretKey, Descriptor, DescriptorPublicKey};

#[test]
fn derive_silent_payment_outputs() {
    let env = TestEnv::new().expect("Getting test environment should be trivial");
    let rpc_client = env.rpc_client();

    let (txid, block_hash, txout) =
        fund_wallet_and_derive_silent_payment_outputs_with_xpriv_sender(rpc_client).unwrap();
    let tx_to_scan = rpc_client
        .get_raw_transaction(&txid, Some(&block_hash))
        .unwrap();

    let prevouts = vec![txout];
    assert_silentpayment_derivation(&tx_to_scan, &prevouts);
}

fn fund_wallet_and_derive_silent_payment_outputs_with_xpriv_sender(
    rpc_client: &impl RpcApi,
) -> anyhow::Result<(Txid, BlockHash, TxOut)> {
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

    let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);
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

    let (sp_code, ..) = get_silentpayment_keys();

    let sp_code_with_amount = [(sp_code.clone(), txout.value - Amount::from_sat(1000))];

    let mut sp_script_pubkeys = sp_sender.send_to(
        &[(selected_outpoint, (spk, privkey_deriv_path))],
        &[sp_code],
    )?;

    let txouts = sp_code_with_amount
        .into_iter()
        .map(|(sp_code, value)| {
            let script_pubkey = {
                let x_only_pubkey = sp_script_pubkeys
                    .get_mut(&sp_code)
                    .expect("deterministic test")
                    .pop()
                    .expect("deterministic test");
                let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

                ScriptBuf::new_p2tr_tweaked(x_only_tweaked)
            };
            TxOut {
                value,
                script_pubkey,
            }
        })
        .collect::<Vec<TxOut>>();

    let silent_payment_txin = TxIn {
        previous_output: selected_outpoint,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    };

    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0).unwrap(),
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

    let block_hashes = rpc_client.generate_to_address(1, &addr).unwrap();
    let sp_block_hash = block_hashes.first().unwrap();
    let block_sp = rpc_client.get_block(sp_block_hash).unwrap();
    assert!(block_sp
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid_sp));

    Ok((txid_sp, *sp_block_hash, txout.clone()))
}
