pub mod encoding;
pub mod hashes;
pub mod receive;
pub mod send;
pub use bitcoin;

use bitcoin::{hashes::Hash, OutPoint};

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
