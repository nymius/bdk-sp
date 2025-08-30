{
  description = "BDK Silent Payments Workshop Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    sp-cli2.url = "../..";
    bdk-cli.url = "github:nymius/bdk-cli/feat/nix-env";
  };
  nixConfig = {
    extra-substituters = ["https://sptabconf7.cachix.org"];
    extra-trusted-public-keys = ["sptabconf7.cachix.org-1:ulR9Y3dF4M6zKXnRRT4+r1Yp52EBMk6yVPKEp1EmdJk="];
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    sp-cli2,
    bdk-cli,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {inherit system;};

        bitcoind = pkgs.stdenv.mkDerivation rec {
          pname = "bitcoin";
          version = "29.0"; # Update to latest version as needed

          src = pkgs.fetchurl {
            url = "https://bitcoincore.org/bin/bitcoin-core-${version}/bitcoin-${version}-${
              if pkgs.stdenv.isDarwin
              then
                if pkgs.stdenv.isAarch64
                then "arm64-apple-darwin"
                else "x86_64-apple-darwin"
              else "x86_64-linux-gnu"
            }.tar.gz";
            sha256 =
              if pkgs.stdenv.isDarwin
              then
                if pkgs.stdenv.isAarch64
                then "sha256-jvA498EVtaSB4ccC86n90BKWng0k3Q9wb0j60VWDdxc="
                else "sha256-NEMcWCoDmd1C4Sdth9JTBsvd4CF/Z0S9VaKUWYZkXdo="
              else "sha256-poHk9s5STDOKEF8hRhNgW6xsM9WMMdxRNbvAK8RYu2w=";
          };

          installPhase = ''
            mkdir -p $out/bin
            cp bin/* $out/bin/
          '';

          meta = {
            description = "Bitcoin Core daemon";
            homepage = "https://bitcoincore.org/";
          };
        };
        workshopEnv = pkgs.buildEnv {
          name = "bdk-sp-workshop-env";
          paths = with pkgs;
            [
              jq
              podman
              qrencode
              xclip
              rust-script
              just
              python311Packages.weasyprint
              presenterm
              bitcoind
              bdk-cli.packages.${system}.bdk-cli
              sp-cli2.packages.${system}.sp-cli2
            ]
            ++ lib.optionals (system != "aarch64-darwin") [
              virtiofsd
            ];
        };
      in {
        formatter = pkgs.alejandra;

        packages = {
          default = workshopEnv;
          workshop-env = workshopEnv;
        };

        devShells = {
          debug = pkgs.mkShell {
            packages = [workshopEnv];
            shellHook = ''
              export PS1="$ "
              export EXTRA_SCRIPTS="$PWD/.bin"
              export BITCOIN_DATA_DIR="$PWD/.bitcoin"
              export BDK_DATA_DIR="$PWD/.bdk"
              export PATH="$EXTRA_SCRIPTS:$PATH"
              export RPC_USER="__cookie__"
              export RPC_PASS=$(cat $BITCOIN_DATA_DIR/signet/.cookie | cut -d ':' -f2)
              export RPC_URL="http://127.0.0.1:38332/"
              export TR_XPRV=$(cat ".tr_xprv")
              export EXT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.external_descriptor")
              export INT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.internal_descriptor")
              export EXTRA_PEER=$(bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet getpeerinfo | jq -r 'map(select(.servicesnames[] | contains ("COMPACT"))) | .[0].addr' | cut -sd ":" -f1)
            '';
          };
          workshop = pkgs.mkShell {
            packages = [workshopEnv];
            shellHook = ''
                          export PS1="$ "

                          export BITCOIN_DATA_DIR="$PWD/.bitcoin"
                          mkdir -p "$BITCOIN_DATA_DIR"

                          export BDK_DATA_DIR="$PWD/.bdk"
                          mkdir -p "$BDK_DATA_DIR"

                          bitcoind -daemonwait -signet -datadir=$BITCOIN_DATA_DIR -daemonwait -txindex -blockfilterindex -peerblockfilters

                          export EXTRA_SCRIPTS="$PWD/.bin"
                          mkdir -p $EXTRA_SCRIPTS

                          cat > "$EXTRA_SCRIPTS/signet-cli" <<'EOF'
              #!/usr/bin/env bash
              bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet $@
              EOF

                          chmod +x "$EXTRA_SCRIPTS/signet-cli"

                          cat > "$EXTRA_SCRIPTS/signet-bdk" <<'EOF'
              #!/usr/bin/env bash
              bdk-cli --datadir "$BDK_DATA_DIR" --network signet wallet -w signet -e "$EXT_DESCRIPTOR" -i "$INT_DESCRIPTOR" -c rpc -u http://localhost:38332/ "$BITCOIN_DATA_DIR/signet/.cookie" -d sqlite "$@"
              EOF

                          chmod +x "$EXTRA_SCRIPTS/signet-bdk"

                          cat > "$EXTRA_SCRIPTS/signet-sp" <<'EOF'
              #!/usr/bin/env bash
              sp-cli2 "$@"
              EOF

                          chmod +x "$EXTRA_SCRIPTS/signet-sp"

                          cat > "$EXTRA_SCRIPTS/regtest-cli" <<'EOF'
              #!/usr/bin/env bash
              just cli "$@"
              EOF

                          chmod +x "$EXTRA_SCRIPTS/regtest-cli"

                          cat > "$EXTRA_SCRIPTS/regtest-bdk" <<'EOF'
              #!/usr/bin/env bash
              just regtest-bdk "$@"
              EOF

                          chmod +x "$EXTRA_SCRIPTS/regtest-bdk"

                          cat > "$EXTRA_SCRIPTS/regtest-sp" <<'EOF'
              #!/usr/bin/env bash
              just regtest-sp "$@"
              EOF

                          chmod +x "$EXTRA_SCRIPTS/regtest-sp"

                          export PATH="$EXTRA_SCRIPTS:$PATH"

                          export RPC_USER="__cookie__"
                          export RPC_PASS=$(cat $BITCOIN_DATA_DIR/signet/.cookie | cut -d ':' -f2)
                          export RPC_URL="http://127.0.0.1:38332/"

                          if [ ! -f "$BDK_DATA_DIR/.external_descriptor" ] || [ ! -f "$BDK_DATA_DIR/.internal_descriptor" ]; then
                            rm -rf $BDK_DATA_DIR/signet
                            rm -rf $BDK_DATA_DIR/regtest
                            XPRV=$(bdk-cli --datadir $BDK_DATA_DIR --network signet key generate | jq -r '.xprv')
                            echo "tr($XPRV/86h/1h/0h/0/*)" > "$BDK_DATA_DIR/.external_descriptor"
                            echo "tr($XPRV/86h/1h/0h/1/*)" > "$BDK_DATA_DIR/.internal_descriptor"
                          fi

                          if [ ! -f ".tr_xprv" ]; then
                            BLOCKCHAININFO=$(bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet getblockchaininfo)
                            HEIGHT=$(echo $BLOCKCHAININFO | jq -r '.blocks')
                            HASH=$(echo $BLOCKCHAININFO | jq -r '.bestblockhash')
                            sp-cli2 create --network signet --birthday-height $HEIGHT --birthday-hash $HASH | jq -r '.tr_xprv' > ".tr_xprv"
                          fi

                          # Start Regtest node on VM machine
                          just init

                          export TR_XPRV=$(cat ".tr_xprv")
                          export EXT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.external_descriptor")
                          export INT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.internal_descriptor")
                          export EXTRA_PEER=$(bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet getpeerinfo | jq -r 'map(select(.servicesnames[] | contains ("COMPACT"))) | .[0].addr' | cut -sd ":" -f1)

                          trap "bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet stop && just stop" EXIT

                          if [[ -z "''${EXTRA_PEER}" ]]; then
                            echo "No compact block filter peers found. Ask for one."
                          else
                            echo "Compact block filter peer available: $EXTRA_PEER";
                          fi
            '';
          };
          default = self.devShells.${system}.workshop;
        };
      }
    );
}
