use crate::{assert_silentpayment_derivation, get_silentpayment_keys, EXTERNAL_DESCRIPTOR};
use bdk_sp::{
    bitcoin::{
        absolute::LockTime, secp256k1::Secp256k1, transaction::Version, Address, Amount, BlockHash,
        Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, Txid,
    },
    send::psbt::derive_sp,
};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use miniscript::{
    descriptor::DescriptorSecretKey, plan::Assets, psbt::PsbtExt, Descriptor, DescriptorPublicKey,
};

#[test]
fn derive_silent_payment_outputs() {
    let env = TestEnv::new().expect("Getting test environment should be trivial");
    let rpc_client = env.rpc_client();

    let (txid, block_hash, txout) =
        fund_wallet_and_derive_silent_payment_outputs_from_psbt(rpc_client).unwrap();
    let tx_to_scan = rpc_client
        .get_raw_transaction(&txid, Some(&block_hash))
        .unwrap();

    let prevouts = vec![txout];
    assert_silentpayment_derivation(&tx_to_scan, &prevouts);
}

fn fund_wallet_and_derive_silent_payment_outputs_from_psbt(
    rpc_client: &impl RpcApi,
) -> anyhow::Result<(Txid, BlockHash, TxOut)> {
    let network = Network::Regtest;
    let secp = Secp256k1::new();
    let (descriptor, keymap) =
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&secp, EXTERNAL_DESCRIPTOR)?;
    // collect assets we can sign for
    //
    let mut assets = Assets::new();

    match &descriptor {
        Descriptor::Wpkh(wpkh) => {
            assets = assets.add(wpkh.clone().into_inner());
        }
        Descriptor::Tr(tr) => {
            assets = assets.add(tr.internal_key().clone());
        }
        _ => todo!("unsupported descriptor type"),
    };

    let funding_desc = descriptor.at_derivation_index(0).unwrap();
    let spk = funding_desc.script_pubkey();

    let plan = funding_desc.plan(&assets).unwrap();
    let addr = Address::from_script(spk.as_script(), network)?;

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

    let selected_outpoint = OutPoint {
        txid,
        vout: output_idx,
    };

    let (sp_code, ..) = get_silentpayment_keys();

    let sp_payment = TxOut {
        value: txout.value - Amount::from_sat(1000),
        script_pubkey: sp_code.get_placeholder_p2tr_spk(),
    };

    let silent_payment_txin = TxIn {
        previous_output: selected_outpoint,
        sequence: plan
            .relative_timelock
            .map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, Sequence::from),
        ..Default::default()
    };

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0).unwrap(),
        input: vec![silent_payment_txin],
        output: vec![sp_payment],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    let psbt_input = &mut psbt.inputs[0];
    plan.update_psbt_input(psbt_input);
    psbt_input.witness_utxo = Some(txout.clone());

    let recipients = vec![sp_code];

    match keymap.iter().next().expect("not empty") {
        (_, DescriptorSecretKey::XPrv(k)) => {
            psbt.sign(&k.xkey, &secp)
                .expect("PSBT signing shouldn't fail");
            psbt.finalize_mut(&secp)
                .map_err(|errors| anyhow::anyhow!("failed to finalize PSBT {errors:?}"))?;
            let psbt_input = &mut psbt.inputs[0];
            plan.update_psbt_input(psbt_input);
            derive_sp(&mut psbt, &k.xkey, &recipients, &secp)?;
            psbt.sign(&k.xkey, &secp)
                .expect("PSBT signing shouldn't fail");
        }
        _ => unimplemented!("external descriptor is P2TR"),
    }

    psbt.finalize_mut(&secp)
        .expect("PSBT finalization shouldn't fail");

    // Get the signed transaction.
    let tx = psbt.extract_tx()?;

    let txid_sp = rpc_client.send_raw_transaction(&tx).unwrap();

    let block_hashes = rpc_client.generate_to_address(1, &addr).unwrap();
    let sp_block_hash = block_hashes.first().unwrap();
    let block_sp = rpc_client.get_block(sp_block_hash).unwrap();
    assert!(block_sp
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid_sp));

    Ok((txid_sp, *sp_block_hash, txout.clone()))
}
