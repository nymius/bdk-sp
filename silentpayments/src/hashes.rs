use bitcoin::{
    hashes::{sha256t_hash_newtype, Hash, HashEngine},
    secp256k1::{PublicKey, Scalar, SecretKey},
};

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);

    pub(crate) struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub(crate) struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

pub fn get_label_tweak(sk: SecretKey, num: u32) -> Scalar {
    let mut eng = LabelHash::engine();
    eng.input(&sk.secret_bytes());
    eng.input(&num.to_be_bytes());
    let hash = LabelHash::from_engine(eng);
    Scalar::from_be_bytes(hash.to_byte_array())
        .expect("hash not in (0, curve_order] range is computationally unreachable")
}

pub fn get_input_hash(lex_min: &[u8; 36], pk_sum: &PublicKey) -> Scalar {
    let mut eng = InputsHash::engine();
    eng.input(lex_min);
    eng.input(&pk_sum.serialize());
    let hash = InputsHash::from_engine(eng);
    Scalar::from_be_bytes(hash.to_byte_array())
        .expect("hash not in (0, curve_order] range is computationally unreachable")
}

pub fn get_shared_secret(shared_secret: PublicKey, k: u32) -> SecretKey {
    let mut eng = SharedSecretHash::engine();
    eng.input(&shared_secret.serialize());
    eng.input(&k.to_be_bytes());
    let hash = SharedSecretHash::from_engine(eng);
    SecretKey::from_slice(&hash.to_byte_array())
        .expect("hash not in (0, curve_order] range is computationally unreachable")
}
