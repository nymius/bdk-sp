//! The full silent payment flow: send to a code, then scan the transaction that pays it.
//!
//! Two parties. A receiver publishes a labelled BIP-352 code and watches for payments to
//! it. A sender holds an ordinary BIP-32 wallet, derives the output script from the keys
//! of the inputs being spent, and pays. The receiver then scans the transaction, finds
//! the payment, learns which label it arrived on, and reproduces the key that spends it.
//!
//! The transaction is never broadcast and its witness is a placeholder, so nothing here
//! is proven against Bitcoin Core. It exists to show the API end to end.
//!
//! Run it with `cargo run --example send_and_scan`.

// The workspace denies printing, which is right for the library and wrong for a program
// whose whole purpose is to be run and watched.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use bdk_sp::{
    bitcoin::{
        absolute::LockTime,
        bip32::{DerivationPath, Xpriv},
        key::TweakedPublicKey,
        secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey},
        transaction::Version,
        Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, XOnlyPublicKey,
    },
    encoding::SilentPaymentCode,
    receive::{scan::Scanner, SpOut},
    send::bip32::XprivSilentPaymentSender,
};
use std::{collections::BTreeMap, str::FromStr};

const NETWORK: Network = Network::Regtest;
const FUNDING_AMOUNT: Amount = Amount::from_sat(100_000);
const PAYMENT_AMOUNT: Amount = Amount::from_sat(10_000);

/// The label the receiver hands this particular sender.
const LABEL: u32 = 7;

fn main() -> Result<()> {
    let mut receiver = Receiver::new()?;
    let sender = Sender::new()?;

    // The receiver publishes a code. Labelling it lets the receiver tell later which
    // sender paid, without the senders being able to tell the codes apart.
    let code = receiver.publish_labelled_code(LABEL)?;
    println!("receiver publishes {code}");

    // The sender pays that code. The output script is derived from the private keys of
    // the inputs being spent, so only the sender can compute it.
    let (tx, prevouts) = sender.pay(&code, PAYMENT_AMOUNT)?;
    println!("sender broadcasts {}", tx.compute_txid());

    // The receiver scans the transaction as it would any other, holding only the scan
    // key. Nothing was communicated between the two parties beyond the code itself.
    let payments = receiver.scan(&tx, &prevouts)?;
    assert_eq!(payments.len(), 1, "the payment should be found");

    let payment = &payments[0];
    assert_eq!(payment.amount, PAYMENT_AMOUNT);
    assert_eq!(
        payment.label,
        Some(LABEL),
        "the payment should be attributed to the label it was sent on"
    );
    println!(
        "receiver finds {} on label {}",
        payment.amount,
        payment.label.expect("labelled")
    );

    // And the coin is spendable: the spend key plus the tweak the scan reported
    // reproduces the output key the transaction actually pays.
    let spend_key = receiver.spend_key(payment)?;
    let secp = Secp256k1::new();
    let output_key = XOnlyPublicKey::from_slice(&payment.script_pubkey.as_bytes()[2..])
        .context("payment should be p2tr")?;
    assert_eq!(spend_key.x_only_public_key(&secp).0, output_key);
    println!("receiver can spend it");

    Ok(())
}

/// The party that publishes a silent payment code and scans for payments to it.
pub struct Receiver {
    scan: SecretKey,
    spend: SecretKey,
    /// Every label this receiver has handed out, keyed by the point it adds to the spend
    /// key. The scanner needs these to recognise a payment made to a labelled code.
    labels: BTreeMap<PublicKey, (Scalar, u32)>,
    secp: Secp256k1<All>,
}

impl Receiver {
    /// The scan and spend keys. A real receiver keeps the spend key offline and gives the
    /// scan key to whatever is watching the chain.
    const SCAN_WIF: &'static str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
    const SPEND_WIF: &'static str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";

    pub fn new() -> Result<Self> {
        Ok(Self {
            scan: secret_key_from_wif(Self::SCAN_WIF)?,
            spend: secret_key_from_wif(Self::SPEND_WIF)?,
            labels: BTreeMap::new(),
            secp: Secp256k1::new(),
        })
    }

    /// The receiver's plain, unlabelled code.
    pub fn code(&self) -> SilentPaymentCode {
        SilentPaymentCode::new_v0(
            self.scan.public_key(&self.secp),
            self.spend.public_key(&self.secp),
            NETWORK,
        )
    }

    /// Derives the code for label `m`, records what is needed to recognise payments to
    /// it, and returns it ready to hand out.
    pub fn publish_labelled_code(&mut self, m: u32) -> Result<SilentPaymentCode> {
        let code = self.code();
        let label = SilentPaymentCode::get_label(self.scan, m);
        let labelled = code.add_label(label).context("label should apply")?;

        // The scanner matches on the point the label adds, which is the difference
        // between the labelled spend key and the plain one.
        let label_point = labelled
            .spend
            .combine(&code.spend.negate(&self.secp))
            .context("label point should be recoverable")?;
        self.labels.insert(label_point, (label, m));

        Ok(labelled)
    }

    /// Finds the payments in `tx` that belong to this receiver.
    pub fn scan(&self, tx: &Transaction, prevouts: &[TxOut]) -> Result<Vec<SpOut>> {
        let scanner = Scanner::new(self.scan, self.code().spend, self.labels.clone());
        scanner.scan_tx(tx, prevouts).context("scan should succeed")
    }

    /// The private key that spends a payment the scan found.
    pub fn spend_key(&self, payment: &SpOut) -> Result<SecretKey> {
        self.spend
            .add_tweak(&payment.tweak.into())
            .context("tweak should apply to the spend key")
    }
}

/// The party that pays a silent payment code out of an ordinary BIP-32 wallet.
pub struct Sender {
    master: Xpriv,
    secp: Secp256k1<All>,
}

impl Sender {
    const MASTER_XPRIV: &'static str = "tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq";

    /// The derivation path of the one output this sender has to spend.
    const PATH: &'static str = "86'/1'/0'/0/0";

    /// The transaction that funded that output. Made up; it is never looked up.
    const FUNDING_TXID: &'static str =
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    pub fn new() -> Result<Self> {
        Ok(Self {
            master: Xpriv::from_str(Self::MASTER_XPRIV).context("valid xpriv")?,
            secp: Secp256k1::new(),
        })
    }

    /// The single P2TR output this sender owns and is about to spend.
    fn utxo(&self) -> Result<(OutPoint, TxOut, DerivationPath)> {
        let path = DerivationPath::from_str(Self::PATH).context("valid derivation path")?;
        let key = self
            .master
            .derive_priv(&self.secp, &path)
            .context("path should be derivable")?
            .private_key;
        let (internal_key, _) = key.x_only_public_key(&self.secp);

        let outpoint = OutPoint {
            txid: Txid::from_str(Self::FUNDING_TXID).context("valid txid")?,
            vout: 0,
        };
        let txout = TxOut {
            value: FUNDING_AMOUNT,
            script_pubkey: ScriptBuf::new_p2tr(&self.secp, internal_key, None),
        };

        Ok((outpoint, txout, path))
    }

    /// Pays `amount` to `code`, returning the transaction and the outputs it spends.
    ///
    /// The prevouts come back because a scanner needs them: the shared secret is derived
    /// from the public keys of the inputs, which live in the outputs being spent.
    pub fn pay(
        &self,
        code: &SilentPaymentCode,
        amount: Amount,
    ) -> Result<(Transaction, Vec<TxOut>)> {
        let (outpoint, prevout, path) = self.utxo()?;
        let inputs = vec![(outpoint, (prevout.script_pubkey.clone(), path))];

        // `send_to` takes every code being paid at once, because the derivation depends on
        // the whole input set, and returns the keys it derived grouped by recipient.
        let sender = XprivSilentPaymentSender::new(self.master);
        let mut derived = sender
            .send_to(&inputs, std::slice::from_ref(code))
            .context("should derive the outputs")?;
        let output_key = derived
            .get_mut(code)
            .context("sent to this code")?
            .pop()
            .context("one output per code")?;

        // The witness is never checked here: a scanner reads the input's public key from
        // the output being spent, not from the witness. A real sender signs at this point.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[vec![0u8; 64]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(output_key),
                ),
            }],
        };

        Ok((tx, vec![prevout]))
    }
}

fn secret_key_from_wif(wif: &str) -> Result<SecretKey> {
    let privkey = PrivateKey::from_wif(wif).context("valid WIF")?;
    SecretKey::from_slice(&privkey.to_bytes()).context("valid secret key")
}
