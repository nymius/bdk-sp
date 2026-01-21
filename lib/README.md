<div align="center">
  <h1>rust-bip352</h1>

  <p>
    <a href="https://github.com/nymius/bdk-sp/blob/master/LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/License-MIT-yellow.svg"/></a>
  </p>
</div>

This crate re-exposes the cryptographic primitives (ECDH, key tweaking, etc.)
from secp256k1 and provides a small set of convenience types to implement BIP 352:

| Type | Description |
|------|-------------|
| `SpCode` | Silent payment code encoding/decoding (Bech32m format) |
| `SpScan` | Helper for organizing scan and spend keys |
| `SpMeta` | Metadata container for silent payment information |
| `SpLabel` | Label support for generating distinct codes |
| `LexMin` | Tracks the lexicographically minimal outpoint |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-bip352 = "0.1.0"
```

To enable serde support:

```toml
[dependencies]
rust-bip352 = { version = "0.1.0", features = ["serde"] }
```

## Usage

### Encoding a Silent Payment Code

```rust
use rust_bip352::SpCode;
use secp256k1::PublicKey;

let scan_pk = PublicKey::from_slice(&[/* ... */])?;
let spend_pk = PublicKey::from_slice(&[/* ... */])?;

let sp_code = SpCode::new_v0(scan_pk, spend_pk, Network::Bitcoin);
println!("{}", sp_code); // sp1qq...
```

### Parsing a Silent Payment Code

```rust
use rust_bip352::SpCode;

let sp_code = SpCode::try_from("sp1qq...")?;
println!("Network: {:?}", sp_code.network);
println!("Scan pubkey: {}", sp_code.scan_pk);
println!("Spend pubkey: {}", sp_code.spend_pk);
```

### Tracking the Lexicographically Minimal Outpoint

```rust
use rust_bip352::LexMin;
use bitcoin_primitives::OutPoint;

let mut tracker = LexMin::default();

for outpoint in transaction_inputs {
    tracker.update(&outpoint);
}

let min_outpoint_bytes = tracker.bytes()?;
```

## Network Prefixes

| Network | HRP |
|---------|-----|
| Bitcoin Mainnet | `sp` |
| Testnet / Signet | `tsp` |
| Regtest | `sprt` |

## See Also

- [BIP-352 Specification](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki).
- [rust-secp256k1 PR#876](https://github.com/rust-bitcoin/rust-secp256k1/pull/876) for cryptographic operations.
