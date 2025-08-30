{
  description = "Dev environment for bdk_sp workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
        naersk-lib = pkgs.callPackage naersk {};

        sp-cli2 = naersk-lib.buildPackage {
          root = ./.;
          cargoBuildOptions = x: x ++ ["--package" "bdk_sp_cli_v2"];
          cargoLock = ./Cargo.lock;
        };
      in {
        formatter = pkgs.alejandra;

        packages.sp-cli2 = sp-cli2;

        defaultPackage = sp-cli2;

        apps = {
          sp-cli2 = flake-utils.lib.mkApp {
            drv = sp-cli2;
            name = "sp-cli2";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustc
            pkgs.cargo
            pkgs.rust-analyzer
            sp-cli2
          ];
        };
      }
    );
}
