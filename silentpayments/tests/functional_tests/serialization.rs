#![allow(non_snake_case)]

use once_cell::sync::Lazy;
use std::collections::HashSet;

use bdk_sp::{
    bitcoin::{
        hashes::hex::FromHex, secp256k1::SecretKey, OutPoint, ScriptBuf, Sequence, TxIn, Txid,
        Witness, XOnlyPublicKey,
    },
    encoding::SilentPaymentCode,
};
use serde::{self, de::Error, Deserialize};

#[derive(Debug, Deserialize)]
pub struct TestCase {
    #[serde(alias = "comment")]
    pub _comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub vin: Vec<SendingVinData>,
    #[serde(deserialize_with = "deserialize_silentpayment_code")]
    pub recipients: Vec<SilentPaymentCode>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "SendingVinDataRaw")]
pub struct SendingVinData {
    pub txin: TxIn,
    pub prevout: ScriptBuf,
    pub sk: SecretKey,
}

#[derive(Debug, Deserialize)]
pub struct SendingVinDataRaw {
    pub txid: Txid,
    pub vout: u32,
    #[serde(deserialize_with = "deserialize_signature")]
    pub scriptSig: ScriptBuf,
    #[serde(default, deserialize_with = "deserialize_witness")]
    pub txinwitness: Witness,
    pub prevout: ScriptPubKey,
    pub private_key: SecretKey,
}

impl From<SendingVinDataRaw> for SendingVinData {
    fn from(value: SendingVinDataRaw) -> Self {
        Self {
            txin: TxIn {
                previous_output: OutPoint {
                    txid: value.txid,
                    vout: value.vout,
                },
                script_sig: value.scriptSig,
                witness: value.txinwitness,
                sequence: Sequence::default(),
            },
            prevout: value.prevout.scriptPubKey.hex,
            sk: value.private_key,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<HashSet<XOnlyPublicKey>>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub vin: Vec<ReceivingVinData>,
    pub key_material: ReceivingKeyMaterial,
    pub labels: Vec<u32>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "ReceivingVinDataRaw")]
pub struct ReceivingVinData {
    pub txin: TxIn,
    pub prevout: ScriptBuf,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingVinDataRaw {
    pub txid: Txid,
    pub vout: u32,
    #[serde(deserialize_with = "deserialize_signature")]
    pub scriptSig: ScriptBuf,
    #[serde(default, deserialize_with = "deserialize_witness")]
    pub txinwitness: Witness,
    pub prevout: ScriptPubKey,
}

impl From<ReceivingVinDataRaw> for ReceivingVinData {
    fn from(value: ReceivingVinDataRaw) -> Self {
        Self {
            txin: TxIn {
                previous_output: OutPoint {
                    txid: value.txid,
                    vout: value.vout,
                },
                script_sig: value.scriptSig,
                witness: value.txinwitness,
                sequence: Sequence::default(),
            },
            prevout: value.prevout.scriptPubKey.hex,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ReceivingKeyMaterial {
    pub scan_priv_key: SecretKey,
    pub spend_priv_key: SecretKey,
}

#[derive(Debug, Deserialize)]
pub struct HexStr {
    pub hex: ScriptBuf,
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKey {
    pub scriptPubKey: HexStr,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    #[serde(deserialize_with = "deserialize_silentpayment_code")]
    pub addresses: Vec<SilentPaymentCode>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct OutputWithSignature {
    pub pub_key: XOnlyPublicKey,
    pub priv_key_tweak: SecretKey,
    pub signature: String,
}

fn deserialize_silentpayment_code<'de, D>(
    deserializer: D,
) -> Result<Vec<SilentPaymentCode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Vec<String> = <Vec<String>>::deserialize(deserializer)?;
    let mut silentpayment_codes = <Vec<SilentPaymentCode>>::new();
    for s in v {
        let code = SilentPaymentCode::try_from(s.as_str()).map_err(D::Error::custom)?;
        silentpayment_codes.push(code);
    }

    Ok(silentpayment_codes)
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<ScriptBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    let script_sig_bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
    let script_sig = ScriptBuf::from_bytes(script_sig_bytes);

    Ok(script_sig)
}

fn deserialize_witness<'de, D>(deserializer: D) -> Result<Witness, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    let witness_bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
    let witness = if witness_bytes.is_empty() {
        Witness::new()
    } else {
        bitcoin::consensus::deserialize::<Witness>(&witness_bytes).map_err(D::Error::custom)?
    };

    Ok(witness)
}

pub static JSON_VECTORS: Lazy<Vec<TestCase>> = Lazy::new(|| {
    let data = std::fs::read_to_string("tests/functional_tests/send_and_receive_test_vectors.json")
        .expect("Failed to read JSON");
    serde_json::from_str(&data).expect("Invalid JSON")
});
