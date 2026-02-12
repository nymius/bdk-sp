{
  description = "Dev environment for bdk_sp workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };
  nixConfig = {
    extra-substituters = ["https://sptabconf7.cachix.org"];
    extra-trusted-public-keys = ["sptabconf7.cachix.org-1:ulR9Y3dF4M6zKXnRRT4+r1Yp52EBMk6yVPKEp1EmdJk="];
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        # Define the Rust version we want to use
        rustVersion = pkgs.rust-bin.stable.latest.default;
      in {
        formatter = pkgs.alejandra;

        packages = {
          sp-cli2 =
            (pkgs.makeRustPlatform {
              cargo = rustVersion;
              rustc = rustVersion;
            })
            .buildRustPackage {
              pname = "sp-cli2";
              version = "0.1.0";

              # Disable cargo-auditable which doesn't support edition 2024
              auditable = false;
              src = ./.;
              cargoLock = {
                lockFile = ./Cargo.lock;
                outputHashes = {
                  "bdk_tx-0.1.0" = "sha256-29weg2aCn+4MHC9DJLSBd09RS7igbTqF/fKRd5u5ef4=";
                };
              };

              buildAndTestSubdir = "cli/v2";
              meta = with pkgs.lib; {
                description = "A lightweight command line bitcoin silent payment wallet powered by BDK";
                homepage = "https://bitcoindevkit.org";
                license = with licenses; [mit];
                mainProgram = "sp-cli2";
              };
            };
        };

        defaultPackage = self.packages.${system}.sp-cli2;

        apps = {
          sp-cli2 = flake-utils.lib.mkApp {
            drv = self.defaultPackage;
            name = "sp-cli2";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustc
            pkgs.cargo
            pkgs.rust-analyzer
            self.packages.${system}.sp-cli2
          ];
        };
      }
    );
}
