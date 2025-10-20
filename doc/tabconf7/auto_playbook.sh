#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_stage() {
    echo -e "${BLUE}==================== $1 ====================${NC}"
}

stages=(
  "STAGE 1: SETUP"
  "STAGE 2: FUND BDK-CLI WALLET"
  "STAGE 3: CREATE A SILENT PAYMENT OUTPUT"
  "STAGE 4: FIND A SILENT PAYMENT OUTPUT"
  "STAGE 5: FUND A TRANSACTION WITH A SILENT PAYMENT OUTPUT"
  "STAGE 6: VERIFY A SILENT PAYMENT CHANGE OUTPUT"
  "STAGE 7: SPEND A SILENT PAYMENT OUTPUT"
)

print_step() {
  echo -e "${YELLOW}Step $1: $2${NC}"
  echo -e "\n${GREEN}ENTER${NC} (to execute), or ${RED}Ctrl+C${NC} (to exit)\n"
}

print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
  echo -e "${RED}✗ $1${NC}"
}

print_info() {
  echo -e "${BLUE}ℹ $1${NC}"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

check_dependencies() {
  local deps=("$@")
  local missing_deps=()

  for dep in "${deps[@]}"; do
    if ! command_exists "$dep"; then
        missing_deps+=("$dep")
    fi
  done

  if [ ${#missing_deps[@]} -ne 0 ]; then
    print_error "Missing dependencies: ${missing_deps[*]}"
    echo "Please install the missing dependencies before proceeding."
    return 1
  fi

  print_success "All dependencies are available: ${deps[*]}"
  return 0
}

execute_step() {
  local stage="$1"
  local step_num="$2"
  local description="$3"
  local command="$4"

  print_stage "${stages[$stage]}"
  print_step "$step_num" "$description"
  printf '%s' "\$ $command"
  read -r
    
  if eval "$command"; then
      echo -e "\nPress ${GREEN}ENTER${NC} to continue to the next step"
      read -r
      clear
      return 0
  else
      print_error "Step $step_num failed"
      echo "Do you want to continue anyway? (y/N)"
      read -r continue_choice
      if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
          exit 1
      fi
      echo
      return 1
  fi
}

check_wallet_exists() {
  local wallet_command="$1"

  if ! eval "$wallet_command balance" >/dev/null 2>&1; then
    print_error "Wallet not accessible with command: $wallet_command"
    return 1
  fi

  return 0
}

trap "just stop" EXIT
clear
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Silent Payment Demo Auto Script      ${NC}"
echo -e "${BLUE}========================================${NC}"
echo

print_info "Checking global dependencies..."
if ! check_dependencies just jq podman cargo; then
  exit 1
fi

execute_step 0 1 "Install dependencies locally and setup regtest environment" "just non_nix_init"

execute_step 0 2 "Check bitcoind is running on regtest" "just cli getblockchaininfo"

execute_step 0 3 "Check bdk-cli wallet was created correctly" "just regtest-bdk balance"

execute_step 0 4 "Check sp-cli wallet was created correctly" "just regtest-sp balance"

execute_step 0 5 "Synchronize bdk-cli wallet" "just regtest-bdk sync"

execute_step 1 6 "Get a new address from bdk-cli wallet" \
  "REGTEST_ADDRESS=\$(just regtest-bdk unused_address | jq -r '.address' | tr -d '\n')"

print_info "Retrieved address: $REGTEST_ADDRESS"

execute_step 1 7 "Mine one block to fund the wallet" "just mine 1 $REGTEST_ADDRESS"

execute_step 1 8 "Mine 100 more blocks to confirm the balance" "just mine 100"

execute_step 1 9 "Synchronize bdk-cli wallet" "just regtest-bdk sync"

execute_step 1 10 "Check balance" "just regtest-bdk balance"

execute_step 2 11 "Get a silent payment code from sp-cli2 wallet" \
    "SP_CODE=\$(just regtest-sp code | jq -r '.silent_payment_code' | tr -d '\\n')"

print_info "Retrieved SP code: $SP_CODE"

execute_step 2 12 "Create transaction spending bdk-cli wallet UTXOs to silent payment" \
    "RAW_TX=\$(just regtest-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee_rate 5 | jq -r '.raw_tx' | tr -d '\\n')"

print_info "Created raw transaction"

execute_step 2 13 "Broadcast transaction using bdk-cli wallet" \
    "TXID=\$(just regtest-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\\n')"

print_info "Transaction ID: $TXID"

execute_step 2 14 "Mine a new block" "just mine 1"

execute_step 2 15 "Synchronize bdk-cli wallet again" "just regtest-bdk sync"

execute_step 3 16 "Synchronize sp-cli2 wallet using RPC" "just regtest-sp scan-rpc"

execute_step 3 17 "Check balance on sp-cli2 wallet" "just regtest-sp balance"

execute_step 3 18 "Check balance on bdk-cli wallet" "just regtest-bdk balance"

execute_step 4 19 "Get a new address from bdk-cli wallet" \
    "REGTEST_ADDRESS=\$(just regtest-bdk unused_address | jq -r '.address' | tr -d '\\n')"

print_info "New address: $REGTEST_ADDRESS"

execute_step 4 20 "Create new transaction with sp-cli2 spending silent payment outputs" \
    "SP_TX=\$(just regtest-sp new-tx --to $REGTEST_ADDRESS:5000 --fee-rate 5 -- \$(printf '%q' \$(cat .regtest_tr_xprv)) | jq -r '.tx' | tr -d '\\n')"

print_info "Created SP transaction"

execute_step 5 21 "Verify the change output derivation" "
  DERIVATION_ORDER=0;
  CHANGE_LABEL=0;
  EXPECTED_CHANGE_SPK=\$(just regtest-sp derive-sp-for-tx \$DERIVATION_ORDER --label \$CHANGE_LABEL --tx-hex $SP_TX | jq -r '.script_pubkey_hex' | tr -d '\\n');
  TX_OUTPUT_SPKS=\$(just cli decoderawtransaction $SP_TX | jq -r '.vout[].scriptPubKey.hex' | tr '\\n' ' ' | tr -d '\\n');
  if [[ -n \$EXPECTED_CHANGE_SPK ]] && [[ \$TX_OUTPUT_SPKS == *\$EXPECTED_CHANGE_SPK* ]]; then
    echo 'Change output matches!';
  else
    echo 'Something went wrong...';
  fi
"

execute_step 6 22 "Broadcast transaction" \
    "SP_TXID=\$(just cli sendrawtransaction $SP_TX | tr -d '\\n')"

print_info "SP Transaction ID: $SP_TXID"

execute_step 6 23 "Mine a new block" "just mine 1"

execute_step 6 24 "Synchronize bdk-cli wallet" "just regtest-bdk sync"

execute_step 6 25 "Synchronize sp-cli2 wallet using RPC scanning" "just regtest-sp scan-rpc"

execute_step 6 26 "Check bdk-cli wallet balance (should have 5000 sats more)" "just regtest-bdk balance"

execute_step 6 27 "Check sp-cli2 wallet balance (should have >5000 sats less)" "just regtest-sp balance"

echo
print_success "Congratulations 🍻!"
echo -e "${GREEN}You have performed your first sat-round trip using silent payments on top of BDK!${NC}"
echo
