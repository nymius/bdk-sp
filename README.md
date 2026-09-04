# `bdk-sp`

<div align="center">
  <p>
    <strong>An experimental crate to research the implementation of silent payment tools in BDK.</strong>
  </p>

  <p>
    <a href="https://coveralls.io/github/bitcoindevkit/bdk-sp?branch=master"><img src="https://coveralls.io/repos/github/bitcoindevkit/bdk-sp/badge.svg?branch=master"/></a>
  </p>
</div>

> [!WARNING]
> Work in progress. Not recommended for use with bitcoin mainnet.

![execution flow enabled by this crate](../media/sp_flow.gif?raw=true)

This is a second iteration of the work initiated in [rust-bip352].
> [!TIP]
> This is a continuation of the changes applied in
> [bdk:feat/silent-payments-with-rust-silentpayments] branch, isolated here for
> better discoverability.
> The [example-crates/justfile] has been refactored to work in isolation from
> the bdk repository.

The project started building on top of [rust-silentpayments], but later
extracted the needed parts from it and started evolving by its own.

The project follows [BIP352] specification, refer to it to learn more about
silentpayments.
The only dependencies from the library are:
- bitcoin
- serde (optional)

## Example

To get started see the `encoding::SilentPaymentCode`, `receive::scan::Scanner`
or `send::bip32::XprivSilentPaymentSender` structs depending on the silent
payment side you want to focus on.

For a complete program covering both sides, see the
[send and scan full flow] example:

```sh
cargo run --example send_and_scan
```

## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on
GitHub. This library is open source licensed under MIT.

[send and scan full flow]: silentpayments/examples/send_and_scan.rs
[rust-silentpayments]: https://github.com/cygnet3/rust-silentpayments
[rust-bip352]: https://github.com/nymius/rust-bip352
[BIP352]: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
[example-crates/justfile]: https://github.com/nymius/bdk-silentpayments/example-crates
[bdk:feat/silent-payments-with-rust-silentpayments]: https://github.com/nymius/bdk/tree/feat/silent-payments-with-rust-silentpayments
