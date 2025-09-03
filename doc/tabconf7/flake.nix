{
  description = "BDK Silent Payments Workshop Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    sp-cli2.url = "github:nymius/bdk-sp/feat/nix-env";
    bdk-cli.url = "github:nymius/bdk-cli/feat/nix-env";
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
                else "sha256-/VAsxyL0zWMPwjIJ/1vzibkmukmlTmU1TSdrdJhBaiE="
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
      in {
        formatter = pkgs.alejandra;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            jq
            podman
            virtiofsd
            qrencode
            qrscan
            xclip
            presenterm
            bitcoind
            bdk-cli.packages.${system}.bdk-cli
            sp-cli2.packages.${system}.sp-cli2
          ];
          shellHook = ''
            export BITCOIN_DATA_DIR="$PWD/.bitcoin"
            mkdir -p "$BITCOIN_DATA_DIR"

            export BDK_DATA_DIR="$PWD/.bdk"
            mkdir -p "$BDK_DATA_DIR"

            bitcoind -signet -datadir=$BITCOIN_DATA_DIR -daemonwait -txindex

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

            XPRV=$(bdk-cli --datadir $BDK_DATA_DIR --network signet key generate | jq -r '.xprv')
            if [ ! -f "$BDK_DATA_DIR/.external_descriptor" ] || [ ! -f "$BDK_DATA_DIR/.internal_descriptor" ]; then
              rm -rf $BDK_DATA_DIR/signet
              echo "tr($XPRV/86h/1h/0h/0/*)" > "$BDK_DATA_DIR/.external_descriptor"
              echo "tr($XPRV/86h/1h/0h/1/*)" > "$BDK_DATA_DIR/.internal_descriptor"
            fi

            export EXT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.external_descriptor")
            export INT_DESCRIPTOR=$(cat "$BDK_DATA_DIR/.internal_descriptor")

            if [ ! -f ".tr_xprv" ]; then
              sp-cli2 create --network signet --birthday $(bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet getblockchaininfo | jq -r '.blocks') | jq -r '.tr_xprv' > ".tr_xprv"
            fi

            # Start Regtest node on VM machine
            just start

            if [ ! -f ".regtest_tr_xprv" ]; then
              DB_PATH=".sp_cli2_regtest.db" sp-cli2 create --network regtest --birthday $(just cli getblockchaininfo | jq -r '.blocks') | jq -r '.regtest_tr_xprv' > ".regtest_tr_xprv"
            fi

            export TR_XPRV=$(cat ".tr_xprv")

            trap "bitcoin-cli --datadir=$BITCOIN_DATA_DIR --chain=signet stop && just stop" EXIT
          '';
        };
      }
    );
}
