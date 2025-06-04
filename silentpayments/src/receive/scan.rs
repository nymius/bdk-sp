use crate::{
    compute_shared_secret,
    receive::{compute_tweak_data, scan_txouts, SpOut, SpReceiveError},
};

use std::collections::BTreeMap;

use bitcoin::{
    secp256k1::{PublicKey, Scalar, SecretKey},
    Transaction, TxOut,
};

pub struct Scanner {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
    label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
}

impl Scanner {
    pub fn new(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
        label_lookup: BTreeMap<PublicKey, (Scalar, u32)>,
    ) -> Self {
        Self {
            scan_sk,
            spend_pk,
            label_lookup,
        }
    }

    pub fn get_shared_secret(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<PublicKey, SpReceiveError> {
        compute_tweak_data(tx, prevouts)
            .map(|partial_secret| compute_shared_secret(&self.scan_sk, &partial_secret))
    }

    pub fn scan_txouts(
        &self,
        tx: &Transaction,
        ecdh_shared_secret: PublicKey,
    ) -> Result<Vec<SpOut>, SpReceiveError> {
        scan_txouts(
            self.spend_pk,
            self.label_lookup.clone(),
            tx,
            ecdh_shared_secret,
        )
    }

    pub fn scan_tx(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Result<Vec<SpOut>, SpReceiveError> {
        let ecdh_shared_secret = self.get_shared_secret(tx, prevouts)?;
        self.scan_txouts(tx, ecdh_shared_secret)
    }
}
