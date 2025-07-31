use bdk_sp::bitcoin::{
    Network, PrivateKey, XOnlyPublicKey,
    bip32::DerivationPath,
    key::Secp256k1,
    secp256k1::{Scalar, SecretKey},
};
use bdk_tx::miniscript::{Descriptor, descriptor::DescriptorSecretKey};
use indexer::indexes::SpIndex;
use std::{collections::HashMap, str::FromStr};

type SpKeyMap = HashMap<XOnlyPublicKey, PrivateKey>;

pub fn populate_sp_keymap(spend_sk: &SecretKey, index: &SpIndex, network: Network) -> SpKeyMap {
    let mut keymap = HashMap::default();
    for (xonly, outpoint) in index.by_xonly() {
        if let Some(sk) = index.by_shared_secret.get(outpoint) {
            let tweaked_sk = spend_sk
                .add_tweak(&Scalar::from(*sk))
                .expect("should succeed");
            keymap.insert(xonly, PrivateKey::new(tweaked_sk, network));
        }
    }
    keymap
}

pub fn get_spend_sk(descriptor_str: &str, network: Network) -> SecretKey {
    let spend_derivation = "0h/0";
    let path = if let Network::Bitcoin = network {
        "352h/0h/0h"
    } else {
        "352h/1h/0h"
    };
    let spend_derivation = DerivationPath::from_str(&format!("{path}/{spend_derivation}")).unwrap();

    let secp = Secp256k1::signing_only();
    let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_str).unwrap();

    match keymap.iter().next().expect("not empty") {
        (_, DescriptorSecretKey::XPrv(privkey)) => {
            let spend_xprv = privkey.xkey.derive_priv(&secp, &spend_derivation).unwrap();
            spend_xprv.private_key
        }
        _ => unimplemented!("only supported single xkeys"),
    }
}
