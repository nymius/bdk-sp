pub mod encoding;
pub mod hashes;
pub mod receive;
pub mod send;
pub use bitcoin;

use bitcoin::{
    hashes::Hash,
    secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey},
    OutPoint, ScriptBuf, TxIn,
};

/// NUM Point used to prune key path spend in taproot
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug)]
pub enum SpInputs {
    P2TR,
    P2WPKH,
    WrappedSegwit,
    P2PKH,
}

pub fn tag_txin(txin: &TxIn, script_pubkey: &ScriptBuf) -> Option<SpInputs> {
    use SpInputs::*;

    if !txin.witness.is_empty() {
        if !txin.script_sig.is_empty()
            && script_pubkey.is_p2sh()
            && txin
                .script_sig
                .redeem_script()
                .filter(|script| script.is_p2wpkh())
                .is_some()
        {
            Some(WrappedSegwit)
        } else if !txin.script_sig.is_empty() {
            None
        } else if script_pubkey.is_p2wpkh() {
            Some(P2WPKH)
        } else if script_pubkey.is_p2tr() {
            if txin
                .witness
                .taproot_control_block()
                .filter(|control_block| control_block[1..33] == NUMS_H)
                .is_some()
            {
                None
            } else {
                Some(P2TR)
            }
        } else {
            None
        }
    } else if !txin.script_sig.is_empty() && script_pubkey.is_p2pkh() {
        Some(P2PKH)
    } else {
        None
    }
}

pub fn get_smallest_lexicographic_outpoint(outpoints: &[OutPoint]) -> [u8; 36] {
    outpoints
        .iter()
        .map(|x| {
            let mut outpoint_bytes = [0u8; 36];
            outpoint_bytes[..32].copy_from_slice(x.txid.to_raw_hash().as_byte_array());
            outpoint_bytes[32..36].copy_from_slice(&x.vout.to_le_bytes());
            outpoint_bytes
        })
        .min()
        .expect("cannot create silent payment script pubkey without outpoints")
}
