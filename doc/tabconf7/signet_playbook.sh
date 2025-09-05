#!/usr/bin/env bash

########################### STAGE 1: setup ####################################

# 1. Launch workshop environment.
nix develop .
# 2. Check bitcoind is running on signet
signet-cli getblockchaininfo
# 3. Check bdk-cli wallet was created correctly
signet-bdk balance
# 4. Check sp-cli wallet was created correctly
signet-sp balance
# 5. Synchronize bdk-cli wallet
signet-bdk sync

########################## STAGE 2: initial funding ###########################

# 6. Get a new address from bdk-cli wallet
SIGNET_ADDRESS=$(signet-bdk unused_address | jq -r '.address' | tr -d '\n')
# 7. Encode the address as a QR code
echo $SIGNET_ADDRESS | qrencode -d 90 -t -utf8 -o -
# 8. Use `padawan` wallet, or whatever other signet wallet to fund the bdk-cli wallet
# 9. Wait for the next block
# 10. Once the new transaction has been mined, synchronize bdk-cli wallet again
signet-bdk sync
# 11. Get a silent payment code from sp-cli2 wallet
SP_CODE=$(signet-sp code | jq -r '.silent_payment_code' | tr -d '\n')
# 12. Create a transaction spending bdk-cli wallet UTXOs to a the previous silent payment code
RAW_TX=$(signet-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee_rate 5 | jq -r '.raw_tx' | tr -d '\n')
# Add a OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# RAW_TX=$(signet-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee 5 --add_string $OP_RETURN)
# 13. Broadcast transaction using bdk-cli wallet
TXID=$(signet-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\n')
# 14. Wait for the next block
# 15. Once the new transaction has been mined, synchronize bdk-cli wallet again
signet-bdk sync
# 16. Now synchronize sp-cli2 wallet usign compact block filter scanning
signet-sp scan-cbf "https://silentpayments.dev/blindbit/"
# 17. Check balance on sp-cli2 wallet
signet-sp balance
# 18. Check balance on bdk-cli wallet
signet-bdk balance

################ STAGE 3: creating silent payment outputs #####################

# 19. Get a new address from bdk-cli wallet
SIGNET_ADDRESS=$(signet-bdk unused_address | jq -r '.address' | tr -d '\n')
# 20. Create new transaction with sp-cli2 spending silent payment outputs
SP_TX=$(signet-sp new-tx --to $SIGNET_ADDRESS:5000 --fee-rate 5 | jq -r '.tx' | tr -d '\n')
# Add a OP_RETURN if you want
# OP_RETURN="Spending to silent payment UTXOs using BDK 🚀
# SP_TX=$(signet-sp new-tx --to $SIGNET_ADDRESS:5000 --data $OP_RETURN --fee_rate 5 | jq -r '.tx' | tr -d '\n')
# This transaction as it is created by a silent payment wallet should have
# derived a silent payment output to receive the change back. That output is
# derived from a labelled silent payment code with label 0, the default
# specified by BIP 352 for change.
# 21. Verify the change output has been correctly derived for $SP_TX

########### STAGE 5: verifying a silent payment change output #################

DERIVATION_ORDER=0
CHANGE_LABEL=0
EXPECTED_CHANGE_SPK=$(signet-sp derive-for-sp-tx $DERIVATION_ORDER --label $CHANGE_LABEL --tx-hex $SP_TX | jq -r '.script_pubkey_hex' | tr -d '\n')
TX_OUTPUT_SPKS=$(signet-cli decoderawtransaction $SP_TX | jq -r '.vout[].scriptPubKey.hex' | tr '\n' ' ' | tr -d '\n')
if [ $TX_OUTPUT_SPKS == *$EXPECTED_CHANGE_SPK* ]; then
  echo "Change output matches!";
else
  echo "Something went wrong...";
fi

############## STAGE 6: spending silent payment outputs #######################

# 22. Broadcast transaction
SP_TXID=$(signet-cli sendrawtransaction $SP_TX | tr -d '\n')
# 23. Wait for the next block
# 24. Once the new transaction has been mined, synchronize bdk-cli wallet again
signet-bdk sync
# 25. Now synchronize sp-cli2 wallet usign compact block filter scanning
signet-sp scan-cbf "https://silentpayments.dev/blindbit/"
# 26. Check bdk-cli wallet balance, should have 5000 sats more than last time we checked
signet-bdk balance
# 27. Check sp-cli2 wallet balance, should have >5000 sats less than last time we checked
signet-sp balance
# 28. Congratulations 🍻 , you have performed your first sat-round trip using silent payments on top of BDK!
