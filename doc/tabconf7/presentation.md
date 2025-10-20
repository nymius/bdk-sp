---
title: Integrating silent payments in BDK
sub_title: advances & challenges
author: nymius
theme:
  name: tokyonight-storm # catppuccin-frappe
---

# Background

<!-- list_item_newlines: 2 -->
- Did some previous contributions to other sections of BDK
- Funded by BDK Foundation to focus on silent payment integration

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# What are we going to do?

> Have your mobile phone at hand, we will be using [`padawan`](https://padawanwallet.com/) signet wallet during the process

- Spend to a silent payment address with `bdk-cli` `create-sp-tx` command
- Scan received silent payments using `sp-cli2` compact block filter scanning
- Derive a silent payment output using a silent payment labelled address
- Verify the change output of a silent payment transaction was correctly derived
- Spend silent payment UTXOs using `sp-cli2` `new-tx` command

<!-- end_slide -->
# Stage 1: setup

Launch workshop environment
```bash
nix develop .
```

<!-- end_slide -->
# Stage 1: setup

Check bitcoind is running on signet
```bash +exec
signet-cli getblockchaininfo
```

<!-- end_slide -->
# Stage 1: setup

Check `bdk-cli` wallet was created correctly
```bash +exec
signet-bdk balance
```
<!-- end_slide -->
# Stage 1: setup

Check `sp-cli2` wallet was created correctly
```bash +exec
signet-sp balance
```

<!-- end_slide -->
# Stage 1: setup

Synchronize `bdk-cli` wallet
```bash +exec +acquire_terminal
signet-bdk sync
```

<!-- end_slide -->
# Stage 2: fund bdk-cli wallet

Get a new address from `bdk-cli` wallet and encode the address as a QR code

> use `padawan` wallet, or whatever other signet wallet to fund the `bdk-cli` wallet

```bash +exec
SIGNET_ADDRESS=$(signet-bdk unused_address | jq -r '.address' | tr -d '\n')

echo -n $SIGNET_ADDRESS | qrencode -d 90 -t utf8 -o -
```

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Recap: silent payments recap

> as we wait for confirmations...

### **RECEIVER**
- publishes two public keys:
    - one for shared secret derivation
    - one to lock funds

### **SENDER**:

- hashes some transaction input data
- combines the key for shared secret derivation with the hash and produces the shared secret
- combines the shared secret with the locking key and produces the output script pubkey
- broadcast the transaction that looks like any P2TR transaction

### **RECEIVER**:
- uses the transaction input data and the private key for shared secret derivation to produce back the shared secret
- with the shared secret and the locking public key the receiver can find its UTXOs

<!-- end_slide -->
# Stage 2: fund bdk-cli wallet

Once the transaction has been mined, synchronize `bdk-cli` wallet to become aware of the funds
```bash +exec
signet-bdk sync
```

<!-- end_slide -->
# Stage 2: fund bdk-cli wallet

Check balance to confirm synchronization discovered the funds
```bash +exec
signet-bdk balance
```

<!-- end_slide -->
# Stage 3: create a silent payment output

Get a silent payment code from `sp-cli2` wallet
```bash +exec +id:sp_code
SP_CODE=$(signet-sp code | jq -r '.silent_payment_code' | tr -d '\n')
/// echo $SP_CODE | xclip -sel clipboard -l 2 && xclip -sel clipboard -o > /dev/null
/// MAX_LEN=60
/// OFFSET="\t"
/// [[ ${#SP_CODE} -le $MAX_LEN ]] && echo $SP_CODE || echo -e "$OFFSET${SP_CODE:0:$(((($MAX_LEN)/2)-3))}...${SP_CODE:$((${#SP_CODE}-(($MAX_LEN)/2)-3))}$OFFSET   "
```

<!-- snippet_output: sp_code -->

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Stage 3: create a silent payment output

<!-- snippet_output: sp_code -->

- `bech32m` encoded string
- The human readable part changes with the network:
    - `sp` for `mainnet`.
    - `tsp` for `signet`, `testnet3` and `testnet4`.
    - `sprt` for `regtest`.

<!-- end_slide -->
# Stage 3: create a silent payment output

Create a transaction spending `bdk-cli` wallet UTXOs to the previous silent payment code
```bash +exec
/// SP_CODE=$(xclip -sel clipboard -o)
/// # TX=$(signet-bdk create_sp_tx --to-sp $SP_CODE:5000 --fee_rate 2)
OP_RETURN="Creating silent payment UTXOs using BDK at TABConf7 🚀"
TX=$(signet-bdk create_sp_tx --to-sp $SP_CODE:5000 --fee_rate 2 --add_string "$OP_RETURN")

RAW_TX=$(echo $TX | jq -r '.raw_tx' | tr -d '\n')
/// echo $RAW_TX | xclip -sel clipboard -l 2 && xclip -sel clipboard -o
```
<!-- end_slide -->
# Stage 3: create a silent payment output

Broadcast transaction using `bdk-cli` wallet
```bash +exec
/// RAW_TX=$(xclip -sel clipboard -o)
TXID=$(signet-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\n')
/// echo $TXID | xclip -sel clipboard -l 2 && xclip -sel clipboard -o
```
<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `create_sp_tx` do?

- Derives placeholder scriptpubkeys from the received silentpayment codes

```rust +exec:rust-script
# //! ```cargo
# //! [dependencies]
# //! bdk_sp = { version = "0.1.0", git = "https://github.com/bitcoindevkit/bdk-sp", tag = "v0.1.0" }
# //! anyhow = "1"
# //! ```
# use bdk_sp::encoding::SilentPaymentCode;
# const SP_CODE: &str = "sp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734ujpez3s";
# fn main() -> Result<(), anyhow::Error> {
  let sp_code = SilentPaymentCode::try_from(SP_CODE)?;

  println!("{}", sp_code.get_placeholder_p2tr_spk());

#  Ok(())
# }
```
- Creates, signs and finalizes a `PSBT` using these placeholder outputs

```rust
let mut psbt = tx_builder.finish()?;

wallet.sign(&mut psbt, SignOptions::default())?;
```

<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `create_sp_tx` do?

- Re adds to the `PSBT` the key derivation paths for each input, scrapped during PSBT finalization

```rust
for (full_input, psbt_input) in unsigned_psbt.inputs.iter().zip(psbt.inputs.iter_mut())
{
    psbt_input.bip32_derivation = full_input.bip32_derivation.clone();
    psbt_input.tap_key_origins = full_input.tap_key_origins.clone();
}
```

- And calls `bdk_sp::send::psbt::derive_sp`

<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `bdk_sp::send::psbt::derive_sp` do?

- Extracts public keys by looking at the prevouts and input witnesses
```rust
# Originally intended for receiving side, two rounds of signing enable it for sending too
pub fn tag_txin(txin: &TxIn, script_pubkey: &ScriptBuf) -> Option<SpInputs>
```
```rust
pub enum SpInputs {
    /// The input spends a P2TR output.
    Tr,
    /// The input spends a P2WPKH output.
    Wpkh,
    /// The input spends a P2WPKH output nested in a P2SH.
    ShWpkh,
    /// The inputs spends a P2PKH output.
    Pkh,
}
```

<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `bdk_sp::send::psbt::derive_sp` do?

- Lookups private keys again using the attached derivation paths
```rust
match pubkey_data {
    (SpInputs::Tr, even_tr_output_key) => get_taproot_secret(psbt_input, k, secp)
    _ => get_non_taproot_secret(psbt_input, k, secp)
}
```
- Uses the private keys and the public data from the silent payment code to create the shared secret
```rust
pub fn create_silentpayment_partial_secret(
    smallest_outpoint_bytes: &[u8; 36],
    spks_with_keys: &[(ScriptBuf, SecretKey)],
) -> Result<SecretKey, SpSendError>
```
<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `bdk_sp::send::psbt::derive_sp` do?

- Derives the silent payment script pubkey outputs and replaces them
```rust
for (sp_code, x_only_pks) in silent_payments.iter() {
    let placeholder_spk = sp_code.get_placeholder_p2tr_spk();

    if let Some(indexes) = placeholder_spk_to_idx.get(&placeholder_spk) {
        // Replace here
    }
}
```

- Then retrieves control to the `create_sp_tx` command handler.

<!-- end_slide -->
# Recap: as we wait for confirmations...

## What does `create_sp_tx` do?

- Clears transaction signatures and signs again with the new outputs
```rust
for psbt_input in psbt.inputs.iter_mut() {
    psbt_input.final_script_sig = None;
    psbt_input.final_script_witness = None;
}

wallet.sign(&mut psbt, SignOptions::default())?;
```

- Finalizes it and publish the resultant raw transaction
```rust
let raw_tx = psbt.extract_tx()?;
```

<!-- end_slide -->
# Recap: as we wait for confirmations...

## Why signing and finalizing before silent payment derivation?

Avoid the premature implementation of complex key introspection logic into wallet.

Is easier to look at the witness to find out if an input is valid for shared secret derivation.

On finalization it's always placed in the `final_script_witness` or `final_script_sig` fields

<!--
speaker_note: |
    Multichain is not a feature of BDK yet.
    `partial_witness` fields should work too, but that was foresighted to change in the future.
-->

## Why re attaching key derivation paths for each input?

Finalization removes derivation path information from the input.

This data is needed during output derivation to find the right private keys associated with each input.

<!--
speaker_note: |
    we need finalization to know what kind of inputs we are looking at, but also we need the derivation paths to know at which paths to derive the private keys.
-->

## Why clearing the signatures prior to signing?

Signatures are not created if inputs are already signed (have a signature in the expected field).

## Why producing a raw transaction and not a PSBT?

We don't want the transaction to be changed after the silent payments outputs are derived.

And we don't want this to be considered a possible way to create multiparty transactions.

<!--
speaker_note: |
If this process were used for multiparty transactions, a user is on risk of sending funds to the void because a malicious counterparty broadcast the transaction with the placeholders instead of the replaced one.
-->

<!-- end_slide -->
# Stage 4: find a silent payment output

Now synchronize `sp-cli2` wallet using compact block filter scanning
```bash +exec +acquire_terminal
signet-sp scan-cbf "https://silentpayments.dev/blindbit/" --extra-peer $EXTRA_PEER
```
<!-- end_slide -->
# Stage 4: find a silent payment output

Once scanning is finished, check balance on `sp-cli2` wallet
```bash +exec
signet-sp balance
```

<!-- end_slide -->
# Stage 4: find a silent payment output

Congratulations, you found the silent payment UTXO!

<!-- end_slide -->
# Stage 4: find a silent payment output

Check the balance on `bdk-cli` wallet has been discounted
```bash +exec
signet-bdk balance
```

<!-- end_slide -->
# Stage 5: fund a transaction with a silent payment output

Get a new address from `bdk-cli` wallet
```bash +exec
SIGNET_ADDRESS=$(signet-bdk unused_address | jq -r '.address' | tr -d '\n')
/// echo $SIGNET_ADDRESS | xclip -sel clipboard -l 2 && xclip -sel clipboard -o
```

<!-- end_slide -->
# Stage 5: fund a transaction with a silent payment output

Create new transaction with `sp-cli2` spending silent payment outputs
```bash +exec
/// SIGNET_ADDRESS=$(xclip -sel clipboard -o)
/// TR_XPRV=$(cat .tr_xprv)
/// # SP_TX=$(signet-sp new-tx --to $SIGNET_ADDRESS:1000 --fee-rate 1 -- $TR_XPRV)
AMOUNT=$(echo "$(($(signet-sp balance | jq -r '.confirmed.spendable | select(. != null)') - 3000))")
OP_RETURN="Spending silent payment UTXOs using BDK at TABConf7 🚀"
SP_TX=$(signet-sp new-tx --to $SIGNET_ADDRESS:$AMOUNT --data "$OP_RETURN" --fee-rate 2 -- $TR_XPRV)

SP_RAW_TX=$(echo $SP_TX | jq -r '.tx' | tr -d '\n')
/// echo $SP_RAW_TX | xclip -sel clipboard -l 2 && xclip -sel clipboard -o
```

<!-- end_slide -->
# Stage 6: verify a silent payment change output

This transaction should derive a silent payment output to receive the change back.

The output is derived from a labelled silent payment code with label 0, the default specified by `BIP 352` for change.

Verify the change output has been correctly derived for it with
```bash +exec
/// SP_TX=$(xclip -sel clipboard -o)
DERIVATION_ORDER=0
CHANGE_LABEL=0

DERIVATION=$(signet-sp derive-sp-for-tx $DERIVATION_ORDER --label $CHANGE_LABEL --tx-hex $SP_TX)
EXPECTED_CHANGE_SPK=$(echo $DERIVATION | jq -r '.script_pubkey_hex' | tr -d '\n')

DECODED_TX=$(signet-cli decoderawtransaction $SP_TX)
TX_OUTPUT_SPKS=$(echo $DECODED_TX | jq -r '.vout[].scriptPubKey.hex' | tr '\n' ' ' | tr -d '\n')

if [[ -n "$EXPECTED_CHANGE_SPK" ]] && [[ $TX_OUTPUT_SPKS == *$EXPECTED_CHANGE_SPK* ]]; then
  echo "Change output matches!";
else
  echo "Something went wrong...";
fi
```

<!-- end_slide -->
# Stage 7: spend a silent payment output

Broadcast transaction
```bash +exec
/// SP_TX=$(xclip -sel clipboard -o)
SP_TXID=$(signet-cli sendrawtransaction $SP_TX | tr -d '\n')
/// echo $SP_TXID | xclip -sel clipboard -l 2 && xclip -sel clipboard -o
```
<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Recap: as we wait for confirmations...

## How does `scan-cbf` work?

1. Synchronizes a `kyoto` cbf node
2. Listens and stores filters
3. On each filter received requests silent payment tweaks (partial secret) from `blindbit` server
4. Computes the silent payment script pubkeys from each tweak and checks against filter
5. If a match is found, request and indexes the block on the wallet
6. All this process is repeated from the birthday of the wallet up to the tip of the chain

<!-- end_slide -->
# Recap: as we wait for confirmations...

## How does `new-tx` work?

Uses placeholder script pubkeys just as `create_sp_tx` to allow coin selection.

Taproot key path spend for all outputs is assumed, so no prior signing nor finalization is required.

The are no suited PSBT fields to provide the tweak data required for output derivation, so `add_sp_data_to_input` was implemented.

<!-- end_slide -->
# Recap: as we wait for confirmations...

## How does `add_sp_data_to_input` work?

`add_sp_data_to_input` fills a propietary field into the PSBT with the spend public key of the silent payment code as key, and the tweak of that particular input as the value.

```rust
pub fn add_sp_data_to_input(
    psbt: &mut Psbt,
    input_index: usize,
    spend_pk: PublicKey,
    tweak: Scalar,
) {
    let prop_key = ProprietaryKey {
        prefix: b"bip352".to_vec(),
        subtype: self::SPEND_PK_SUBTYPE,
        key: spend_pk.serialize().to_vec(),
    };

    let derivation_data = tweak.to_be_bytes().to_vec();

    if let Some(input) = psbt.inputs.get_mut(input_index) {
        input.proprietary.insert(prop_key, derivation_data);
    }
}
```

Once this information is added, `new-tx` calls `derive-sp`, just as with `bdk_cli::create_sp_tx`.

<!-- end_slide -->
# Recap: as we wait for confirmations...

## Does `derive_sp` do something different?

`derive_sp` has a gated feature just for silent payment wallets, to recognize first this field, and shortcircuit any other lookup method to derive the right private key for the input.

```rust
if let Ok(Some(secret)) = get_sp_secret(psbt_input, k, secp) {
    Some(secret)
} else {
    match pubkey_data {
        (SpInputs::Tr, even_tr_output_key) => get_taproot_secret(psbt_input, k, secp),
        _ => get_non_taproot_secret(psbt_input, k, secp)
    }
}
```

Finally, `new-tx` calls `sign_sp`.

<!-- end_slide -->
# Recap: as we wait for confirmations...

## How does `sign_sp` work?

`sign_sp` is the final function that takes these inputs, extracts the tweaks from the propietary field, combines it with the spend private key and signs each of the silent payment inputs.

```rust
pub fn sign_sp<C, K>(psbt: &mut Psbt, k: &K, secp: &Secp256k1<C>)
where
    C: Signing + Verification,
    K: GetKey,
```

Then, `new-tx` finalizes and extracts the PSBT.

<!-- end_slide -->
# Stage 7: spend a silent payment output

Once the new transaction has been mined, synchronize `bdk-cli` wallet again
```bash +exec
signet-bdk sync
```

<!-- end_slide -->
# Stage 7: spend a silent payment output

Now synchronize `sp-cli2` wallet using compact block filter scanning
```bash +exec +acquire_terminal
signet-sp scan-cbf "https://silentpayments.dev/blindbit/" --extra-peer $EXTRA_PEER
```

<!-- end_slide -->
# Stage 7: spend a silent payment output

Check `bdk-cli` wallet balance, should have more sats than last time we checked
```bash +exec
signet-bdk balance
```

<!-- end_slide -->
# Stage 7: spend a silent payment output

Check `sp-cli2` wallet balance, should have less sats than last time we checked
```bash +exec
signet-sp balance
```

<!-- end_slide -->
# Stage 7: spend a silent payment output

Congratulations 🍻 , you have performed your first sat-round trip using silent payments on top of BDK!

<!-- end_slide -->
# Reflections

## What was the target of this implementation?

The work showed on this presentation was targeted as a quick way to provide functionality using BDK primitives.

This enables a fast feedback loop and a good comprehension of the landscape of silent payment integration on wallets.

This allowed the recognition of the upstream gaps and the features required on BDK.

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Challenges

- The `rust-secp256k1` bindings were WIP and the API wasn't stable.
- BDK transaction building process is PSBT centric
- Silent payment PSBT support is tricky:
    - BIP 374 and BIP 375 are not finalized yet, and its implementation in `rust-psbt` was going to require more work there than in BDK
    - `tweaks` used in silent payments for signing, like `bip32_derivation_path` or `tap_merkle_root`.
- BDK structures were not flexible enough:
    - there's no way to index partial secrets in the current BDK `TxGraph`.

This implied higher complexity for implementing multiparty silent payment transaction with PSBTs.

By aiming this implementation for single party only, the goal was made fairly achievable.

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Next steps

- Implement `libsecp256k1` bindings in `rust-secp256k1`.
- Push for the specification of a new PSBT field to add silent payment tweaks in the same fashion than `bip32_derivation_path` and `tap_merkle_root`.
- Implement BIP 374 and BIP 375 features on `rust-psbt`.
- Implement `KeyRequest` for silent payments on `rust-psbt`.
- Implement `miniscript` `planning` for silent payment descriptor.
- Implement silent payment queries for `PlannedUtxo`s: `Is this UTXO available for silent payment derivation?`
- Implement the storage of meta data on BDK `TxGraph`.

<!-- end_slide -->
<!-- new_lines: 20 -->
<!-- alignment: center -->

# Questions?

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Contact

- github: `nymius`
- discord: `#silent-payments` channel on [BDK server](https://discord.gg/dstn4dQ)

<!-- end_slide -->
<!-- list_item_newlines: 2 -->
# Resources

- [BIP 352: Silent Payments V1](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP 375: PSBTs for Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
- [BIP 374: DLEQ for PSBT for Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)

<!-- end_slide -->
<!-- new_lines: 20 -->
<!-- alignment: center -->
# Thanks!
