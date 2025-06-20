#![allow(non_snake_case)]

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use once_cell::sync::Lazy;

use csv::ReaderBuilder;
use serde::{self, Deserialize, de::Error};

#[derive(Debug, Deserialize)]
pub struct VerifyTestCase {
    #[serde(alias = "index")]
    pub _index: usize,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub point_G: PublicKey,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub point_A: PublicKey,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub point_B: PublicKey,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub point_C: PublicKey,
    #[serde(deserialize_with = "deserialize_proof")]
    pub proof: [u8; 64],
    #[serde(deserialize_with = "deserialize_message")]
    pub message: Option<[u8; 32]>,
    #[serde(deserialize_with = "deserialize_bool")]
    pub result_success: bool,
    #[serde(alias = "comment")]
    pub _comment: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateTestCase {
    #[serde(alias = "index")]
    pub _index: usize,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub point_G: PublicKey,
    #[serde(deserialize_with = "deserialize_maybe_secretkey")]
    pub scalar_a: Option<SecretKey>,
    #[serde(deserialize_with = "deserialize_maybe_pubkey")]
    pub point_B: Option<PublicKey>,
    #[serde(deserialize_with = "deserialize_32_bytes")]
    pub auxrand_r: [u8; 32],
    #[serde(deserialize_with = "deserialize_message")]
    pub message: Option<[u8; 32]>,
    #[serde(deserialize_with = "deserialize_result_proof")]
    pub result_proof: Option<[u8; 64]>,
    #[serde(alias = "comment")]
    pub _comment: String,
}

fn deserialize_maybe_secretkey<'de, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(SecretKey::deserialize(deserializer).ok())
}

fn deserialize_maybe_pubkey<'de, D>(deserializer: D) -> Result<Option<PublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(bitcoin::PublicKey::deserialize(deserializer)
        .ok()
        .map(|pk| pk.inner))
}

fn deserialize_proof<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    let proof_bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
    proof_bytes
        .try_into()
        .map_err(|_| D::Error::custom("cannot deserialize as array"))
}

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    if v == "TRUE" {
        Ok(true)
    } else if v == "FALSE" {
        Ok(false)
    } else {
        Err(D::Error::custom("not boolean value"))
    }
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bitcoin::PublicKey::deserialize(deserializer).map(|pk| pk.inner)
}

fn deserialize_32_bytes<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    let bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| D::Error::custom("cannot deserialize as array"))
}

fn deserialize_result_proof<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    if v != "INVALID" {
        let bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("cannot deserialize as array"))
            .map(Some)
    } else {
        Ok(None)
    }
}

fn deserialize_message<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: String = String::deserialize(deserializer)?;
    if !v.is_empty() {
        let message_bytes: Vec<u8> = FromHex::from_hex(&v).map_err(D::Error::custom)?;
        message_bytes
            .try_into()
            .map_err(|_| D::Error::custom("cannot deserialize as array"))
            .map(Some)
    } else {
        Ok(None)
    }
}

pub static VERIFY_PROOF_VECTORS: Lazy<Vec<VerifyTestCase>> = Lazy::new(|| {
    let data = std::fs::read_to_string("tests/functional_tests/test_vectors_verify_proof.csv")
        .expect("Failed to read JSON");
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(data.as_bytes());
    rdr.deserialize()
        .collect::<Result<Vec<VerifyTestCase>, _>>()
        .expect("should deserialize")
});

pub static GENERATE_PROOF_VECTORS: Lazy<Vec<GenerateTestCase>> = Lazy::new(|| {
    let data = std::fs::read_to_string("tests/functional_tests/test_vectors_generate_proof.csv")
        .expect("Failed to read JSON");
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(data.as_bytes());
    rdr.deserialize()
        .collect::<Result<Vec<GenerateTestCase>, _>>()
        .expect("should deserialize")
});
