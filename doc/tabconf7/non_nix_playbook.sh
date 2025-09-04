#!/usr/bin/env bash

########################### STAGE 1: setup ####################################

# 1. Install dependencies locally and setup regtest environment
just non_nix_init
# 2. Check bitcoind is running on regtest
just cli getblockchaininfo
# 3. Check bdk-cli wallet was created correctly
just regtest-bdk balance
# 4. Check sp-cli wallet was created correctly
just regtest-sp balance
# 5. Synchronize bdk-cli wallet
just regtest-bdk sync

###################### STAGE 2: fund bdk-cli wallet ###########################

# 6. Get a new address from bdk-cli wallet
REGTEST_ADDRESS=$(just regtest-bdk unused_address | jq -r '.address' | tr -d '\n')
# 7. Mine a few more blocks to fund the wallet
just mine 1 $REGTEST_ADDRESS
# 8. Mine some of them to the internal wallet to confirm the bdk-cli balance
just mine 101
# 9. Synchronize bdk-cli wallet
just regtest-bdk sync
# 10. Check balance
just regtest-bdk balance

################ STAGE 3: create a silent payment output ######################

# 11. Get a silent payment code from sp-cli2 wallet
SP_CODE=$(just regtest-sp code | jq -r '.silent_payment_code' | tr -d '\n')
# 12. Create a transaction spending bdk-cli wallet UTXOs to a the previous silent payment code
RAW_TX=$(just regtest-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee_rate 5 | jq -r '.raw_tx' | tr -d '\n')
# Add an OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# RAW_TX=$(just regtest-bdk create-sp-tx --to-sp $SP_CODE:10000 --fee 5 --add_string $OP_RETURN)
# 13. Broadcast transaction using bdk-cli wallet
TXID=$(just regtest-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\n')
# 14. Mine a new block
just mine 1
# 15. Once the new transaction has been mined, synchronize bdk-cli wallet again
just regtest-bdk sync

################## STAGE 4: find a silent payment output ######################

# 16. Now synchronize sp-cli2 wallet using RPC
just regtest-sp scan-rpc
# 17. Check balance on sp-cli2 wallet
just regtest-sp balance
# 18. Check balance on bdk-cli wallet
just regtest-bdk balance

########## STAGE 5: fund a transaction with a silent payment output ###########

# 19. Get a new address from bdk-cli wallet
REGTEST_ADDRESS=$(just regtest-bdk unused_address | jq -r '.address' | tr -d '\n')
# 20. Create new transaction with sp-cli2 spending silent payment outputs
SP_TX=$(just regtest-sp new-tx --to $REGTEST_ADDRESS:5000 --fee-rate 5 -- $(printf '%q' $(cat .regtest_tr_xprv)) | jq -r '.tx' | tr -d '\n')
# Add a OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# SP_TX=$(just regtest-sp new-tx --to $REGTEST_ADDRESS:5000 --data $OP_RETURN --fee_rate 5 | jq -r '.tx' | tr -d '\n')

############ STAGE 6: verify a silent payment change output ###################

# This transaction as it is created by a silent payment wallet should have
# derived a silent payment output to receive the change back. That output is
# derived from a labelled silent payment code with label 0, the default
# specified by BIP 352 for change.
# 21. Verify the change output has been correctly derived for $SP_TX
DERIVATION_ORDER=0
CHANGE_LABEL=0
EXPECTED_CHANGE_SPK=$(just regtest-sp derive-sp-for-tx $DERIVATION_ORDER --label $CHANGE_LABEL --tx-hex $SP_TX | jq -r '.script_pubkey_hex' | tr -d '\n')
TX_OUTPUT_SPKS=$(just cli decoderawtransaction $SP_TX | jq -r '.vout[].scriptPubKey.hex' | tr '\n' ' ' | tr -d '\n')
if [[ -n "$EXPECTED_CHANGE_SPK" ]] && [[ $TX_OUTPUT_SPKS == *$EXPECTED_CHANGE_SPK* ]]; then
  echo "Change output matches!";
else
  echo "Something went wrong...";
fi

################# STAGE 7: spend a silent payment output ######################

# 22. Broadcast transaction
SP_TXID=$(just cli sendrawtransaction $SP_TX | tr -d '\n')
# 23. Mine a new block
just mine 1
# 24. Once the new transaction has been mined, synchronize bdk-cli wallet again
just regtest-bdk sync
# 25. Now synchronize sp-cli2 wallet using RPC scanning
just regtest-sp scan-rpc
# 26. Check bdk-cli wallet balance, should have 5000 sats more than last time we checked
just regtest-bdk balance
# 27. Check sp-cli2 wallet balance, should have >5000 sats less than last time we checked
just regtest-sp balance
# 28. Congratulations 🍻 , you have performed your first sat-round trip using silent payments on top of BDK!
