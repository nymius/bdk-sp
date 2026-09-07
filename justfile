alias b := build
alias c := check
alias f := fmt
alias t := test
alias p := pre-push
alias ts := test-slow
alias ta := test-all

[doc("List all available commands.")]
default:
  just --list --unsorted

[doc("Build the project")]
build:
  cargo build --workspace --exclude sp_fuzz

[doc("Check code: formatting, compilation, linting, and commit signature")]
check:
  cargo +nightly fmt --all -- --check
  cargo check --workspace --exclude sp_fuzz --exclude bdk_sp_cli_v1 --exclude bdk_sp_cli_v2 --all-features
  cargo clippy --all-features --all-targets -- -D warnings
  @[ "$(git log --pretty='format:%G?' -1 HEAD)" = "N" ] && \
      echo "\n⚠️  Unsigned commit: BDK requires that commits be signed." || \
      true

[doc("Format all code")]
fmt:
  cargo +nightly fmt

[doc("Run fast tests  on the workspace with all features (skips tests annotated with #[ignore])")]
test:
  cargo test --workspace --exclude sp_fuzz --exclude bdk_sp_cli_v1 --exclude bdk_sp_cli_v2 --all-features

[doc("Run pre-push suite: format, check, and test")]
pre-push: fmt check test

[doc("Run the slow tests that `test`/`pre-push` skip")]
test-slow:
  cargo test --workspace --exclude sp_fuzz --exclude bdk_sp_cli_v1 --exclude bdk_sp_cli_v2 --all-features -- --ignored slow::

[doc("Run all tests including slow/ignored tests on the workspace with all features")]
test-all: pre-push test-slow