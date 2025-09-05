#!/usr/bin/env bash

########################### STAGE 1: setup ####################################

# 1. Launch workshop environment.
nix develop .
# 2. Check bitcoind is running on regtest
regtest-cli getblockchaininfo
# 3. Check bdk-cli wallet was created correctly
regtest-bdk balance
# 4. Check sp-cli wallet was created correctly
regtest-sp balance
# 5. Synchronize bdk-cli wallet
regtest-bdk sync

########################## STAGE 2: initial funding ###########################

# 6. Get a new address from bdk-cli wallet
REGTEST_ADDRESS=$(regtest-bdk unused_address | jq -r '.address' | tr -d '\n')
# 7. Mine a few more blocks to fund the wallet
just mine 101 $REGTEST_ADDRESS
# 8. Synchronize bdk-cli wallet
regtest-bdk sync
# 9. Check balance
regtest-bdk balance
# 10. Get a silent payment code from sp-cli2 wallet
SP_CODE=$(regtest-sp code | jq -r '.silent_payment_code' | tr -d '\n')
# 11. Create a transaction spending bdk-cli wallet UTXOs to a the previous silent payment code
RAW_TX=$(regtest-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee_rate 5 | jq -r '.raw_tx' | tr -d '\n')
# Add a OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# RAW_TX=$(regtest-bdk create-sp-tx --to-sp $SP_CODE:10000 --fee 5 --add_string $OP_RETURN)
# 12. Broadcast transaction using bdk-cli wallet
TXID=$(regtest-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\n')
# 13. Mine a new block
just mine 1
# 14. Once the new transaction has been mined, synchronize bdk-cli wallet again
regtest-bdk sync
# 15. Now synchronize sp-cli2 wallet using RPC
regtest-sp scan-rpc
# 16. Check balance on sp-cli2 wallet
regtest-sp balance
# 17. Check balance on bdk-cli wallet
regtest-bdk balance

################ STAGE 3: creating silent payment outputs #####################

# 18. Get a new address from bdk-cli wallet
REGTEST_ADDRESS=$(regtest-bdk unused_address | jq -r '.address' | tr -d '\n')
# 19. Create new transaction with sp-cli2 spending silent payment outputs
SP_TX=$(regtest-sp new-tx --to $REGTEST_ADDRESS:5000 --fee-rate 5 -- $(printf '%q' $(cat .regtest_tr_xprv)) | jq -r '.tx' | tr -d '\n')
# Add a OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# SP_TX=$(regtest-sp new-tx --to $REGTEST_ADDRESS:5000 --data $OP_RETURN --fee_rate 5 | jq -r '.tx' | tr -d '\n')

########### STAGE 5: verifying a silent payment change output #################

# This transaction as it is created by a silent payment wallet should have
# derived a silent payment output to receive the change back. That output is
# derived from a labelled silent payment code with label 0, the default
# specified by BIP 352 for change.
# 20. Verify the change output has been correctly derived for $SP_TX
DERIVATION_ORDER=0
CHANGE_LABEL=0
EXPECTED_CHANGE_SPK=$(regtest-sp derive-sp-for-tx $DERIVATION_ORDER --label $CHANGE_LABEL --tx-hex $SP_TX | jq -r '.script_pubkey_hex' | tr -d '\n')
TX_OUTPUT_SPKS=$(regtest-cli decoderawtransaction $SP_TX | jq -r '.vout[].scriptPubKey.hex' | tr '\n' ' ' | tr -d '\n')
if [[ $TX_OUTPUT_SPKS == *$EXPECTED_CHANGE_SPK* ]]; then
  echo "Change output matches!";
else
  echo "Something went wrong...";
fi

############## STAGE 6: spending silent payment outputs #######################

# 21. Broadcast transaction
SP_TXID=$(regtest-cli sendrawtransaction $SP_TX | tr -d '\n')
# 22. Mine a new block
just mine 1
# 23. Once the new transaction has been mined, synchronize bdk-cli wallet again
regtest-bdk sync
# 24. Now synchronize sp-cli2 wallet usign RPC scanning
regtest-sp scan-rpc
# 25. Check bdk-cli wallet balance, should have 5000 sats more than last time we checked
regtest-bdk balance
# 26. Check sp-cli2 wallet balance, should have >5000 sats less than last time we checked
regtest-sp balance
# 27. Congratulations 🍻 , you have performed your first sat-round trip using silent payments on top of BDK!
