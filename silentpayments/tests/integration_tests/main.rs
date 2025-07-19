use bdk_sp::{
    bitcoin::{
        secp256k1::{Secp256k1, SecretKey},
        Network, PrivateKey, Transaction, TxOut,
    },
    encoding::SilentPaymentCode,
    receive::scan::Scanner,
};
use std::collections::BTreeMap;

mod psbt;
mod xpriv_sender;

const EXTERNAL_DESCRIPTOR: &str = "tr([3794bb41]tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq/86'/1'/0'/0/*)#dg6yxkuh";
const SILENT_PAYMENT_SPEND_PRIVKEY: &str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";
const SILENT_PAYMENT_SCAN_PRIVKEY: &str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
const SILENT_PAYMENT_ENCODED: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

fn assert_silentpayment_derivation(tx: &Transaction, prevouts: &[TxOut]) {
    let secp = Secp256k1::new();
    let (sp_code, scan_sk, spend_sk) = get_silentpayment_keys();

    let scanner = Scanner::new(scan_sk, sp_code.spend, <BTreeMap<_, _>>::new());

    let found_spouts = scanner.scan_tx(tx, prevouts).expect("should find spouts");

    assert!(!found_spouts.is_empty());

    for sp_output in found_spouts {
        let output_sk = spend_sk.add_tweak(&sp_output.tweak.into()).unwrap();
        // Check the output is spendable
        assert_eq!(output_sk.x_only_public_key(&secp).0, sp_output.xonly_pubkey);
    }
}

pub fn get_silentpayment_keys() -> (SilentPaymentCode, SecretKey, SecretKey) {
    let secp = Secp256k1::new();
    let spend_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SPEND_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let scan_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SCAN_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    let sp_code = SilentPaymentCode::new_v0(
        scan_privkey.public_key(&secp),
        spend_privkey.public_key(&secp),
        Network::Regtest,
    );

    assert_eq!(sp_code.to_string(), SILENT_PAYMENT_ENCODED);

    (sp_code, scan_privkey, spend_privkey)
}
