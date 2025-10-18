#![allow(non_snake_case)]

use bitcoin::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey};

sha256t_hash_newtype! {
    pub(crate) struct DleqAuxTag = hash_str("BIP0374/aux");

    /// BIP0374-tagged hash with tag \"aux\".
    ///
    /// This is used for computing the DLEQ proof
    #[hash_newtype(forward)]
    pub(crate) struct DleqAuxHash(_);

    pub(crate) struct DleqNonceTag = hash_str("BIP0374/nonce");

    /// BIP0374-tagged hash with tag \"nonce\".
    ///
    /// This is used for computing the DLEQ proof
    #[hash_newtype(forward)]
    pub(crate) struct DleqNonceHash(_);

    pub(crate) struct DleqChallengeTag = hash_str("BIP0374/challenge");

    /// BIP0374-tagged hash with tag \"challenge\".
    ///
    /// This hash type is for computing the DLEQ challenge
    #[hash_newtype(forward)]
    pub(crate) struct DleqChallengeHash(_);
}

#[derive(Debug)]
pub enum DleqError {
    RangeError(bitcoin::secp256k1::scalar::OutOfRangeError),
    Secp256k1Error(bitcoin::secp256k1::Error),
    VerificationFailed,
}

impl From<bitcoin::secp256k1::scalar::OutOfRangeError> for DleqError {
    fn from(e: bitcoin::secp256k1::scalar::OutOfRangeError) -> Self {
        Self::RangeError(e)
    }
}

impl From<bitcoin::secp256k1::Error> for DleqError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl std::fmt::Display for DleqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::RangeError(e) => writeln!(f, "{e}"),
            Self::Secp256k1Error(e) => writeln!(f, "{e}"),
            Self::VerificationFailed => writeln!(f, "the verification of the proof failed"),
        }
    }
}

impl std::error::Error for DleqError {}

fn xor_bytes(rhs: [u8; 32], lhs: [u8; 32]) -> [u8; 32] {
    let mut xored_bytes = [0u8; 32];
    for (idx, byte) in rhs.iter().zip(lhs).map(|(x, y)| x ^ y).enumerate() {
        xored_bytes[idx] = byte
    }
    xored_bytes
}

pub fn dleq_generate_proof(
    a: SecretKey,
    B: PublicKey,
    r: &[u8; 32],
    G: PublicKey,
    m: Option<&[u8; 32]>,
) -> Result<[u8; 64], DleqError> {
    let secp = Secp256k1::new();
    let A = G.mul_tweak(&secp, &Scalar::from(a))?;
    let C = B.mul_tweak(&secp, &Scalar::from(a))?;
    let r = {
        let mut eng = DleqAuxHash::engine();
        eng.input(r);
        let hash = DleqAuxHash::from_engine(eng);
        Scalar::from_be_bytes(hash.to_byte_array()).expect("hash value greater than curve order")
    };
    let t = xor_bytes(a.secret_bytes(), r.to_be_bytes());
    let rand = {
        let mut eng = DleqNonceHash::engine();
        eng.input(&t);
        eng.input(&A.serialize());
        eng.input(&C.serialize());
        if let Some(msg) = m {
            eng.input(msg);
        }
        let hash = DleqNonceHash::from_engine(eng);
        // NOTE: Why big endian bytes??? Doesn't matter. Look at: https://github.com/rust-bitcoin/rust-bitcoin/issues/1896
        SecretKey::from_slice(&hash.to_byte_array()).expect("hash value greater than curve order")
    };
    let R1 = G.mul_tweak(&secp, &Scalar::from(rand))?;
    let R2 = B.mul_tweak(&secp, &Scalar::from(rand))?;
    let e = dleq_challenge(A, B, C, R1, R2, m, G);
    let s = rand.add_tweak(&Scalar::from(a.mul_tweak(&e)?))?;
    let proof: [u8; 64] = [e.to_be_bytes(), s.secret_bytes()]
        .concat()
        .try_into()
        .expect("e and s are both 32 bytes, so proof should be 64 bytes long");
    if dleq_verify_proof(A, B, C, &proof, G, m)? {
        Ok(proof)
    } else {
        Err(DleqError::VerificationFailed)
    }
}

fn dleq_challenge(
    A: PublicKey,
    B: PublicKey,
    C: PublicKey,
    R1: PublicKey,
    R2: PublicKey,
    m: Option<&[u8; 32]>,
    G: PublicKey,
) -> Scalar {
    let mut eng = DleqChallengeHash::engine();
    eng.input(&A.serialize());
    eng.input(&B.serialize());
    eng.input(&C.serialize());
    eng.input(&G.serialize());
    eng.input(&R1.serialize());
    eng.input(&R2.serialize());
    if let Some(msg) = m {
        eng.input(msg);
    }
    let hash = DleqChallengeHash::from_engine(eng);
    Scalar::from_be_bytes(hash.to_byte_array()).expect("hash value greater than curve order")
}

pub fn dleq_verify_proof(
    A: PublicKey,
    B: PublicKey,
    C: PublicKey,
    proof: &[u8; 64],
    G: PublicKey,
    m: Option<&[u8; 32]>,
) -> Result<bool, DleqError> {
    let secp = Secp256k1::new();
    let e: [u8; 32] = core::array::from_fn(|i| proof[i]);
    let s: [u8; 32] = core::array::from_fn(|i| proof[i + 32]);
    let e_scalar = Scalar::from_be_bytes(e)?;
    let s_scalar = Scalar::from_be_bytes(s)?;
    let S1 = G.mul_tweak(&secp, &s_scalar)?;
    let E1 = A.mul_tweak(&secp, &e_scalar)?;
    let R1 = S1.combine(&E1.negate(&secp))?;
    let S2 = B.mul_tweak(&secp, &s_scalar)?;
    let E2 = C.mul_tweak(&secp, &e_scalar)?;
    let R2 = S2.combine(&E2.negate(&secp))?;

    let challenge = dleq_challenge(A, B, C, R1, R2, m, G);
    if e_scalar != challenge {
        Ok(false)
    } else {
        Ok(true)
    }
}
