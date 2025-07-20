# Contributing to `bdk-sp`

This project welcomes contributions from anyone via peer review, documentation, testing, and patches, regardless of experience, age, or other factors. Cryptocurrency protocol development requires rigor, adversarial thinking, thorough testing, and risk minimization, as bugs can cost users money.

## Communications Channels

Communication occurs in the `#silent-payments` channel on the [BDK Discord server](https://discord.gg/dstn4dQ) and on GitHub via [issues](https://github.com/bitcoindevkit/bdk-sp/issues) and [pull requests](https://github.com/bitcoindevkit/bdk-sp/pulls).

## Useful Knowledge

No requirements to contribute, but familiarity with BIPs 352[^1], 375[^2], 374[^3], and the light client specification[^4] helps, as they drive this repository's content.

## Contribution Workflow

The codebase uses the contributor workflow, where everyone submits patch proposals via pull requests. This facilitates social contribution, easy testing, and peer review.

To contribute a patch:

1. Fork the repository.
2. Create a topic branch.
3. Commit patches.

Commits should be atomic with easy-to-read diffs. Do not mix formatting fixes or code moves with actual changes. Each commit should compile and pass tests to ensure tools like git bisect work properly.

When adding features, consider long-term technical debt. Cover new features with functional tests where possible.

For refactoring, structure PRs for easy review and split into multiple small, focused PRs if needed.

The minimal supported Rust version is **1.63.0** (enforced by CI).

Commits should describe the issue fixed and the solution's rationale.

Consider [cbeams guidelines](https://chris.beams.io/posts/git-commit/) to write commit messages. Apply ["Conventional Commits 1.0.0"](https://www.conventionalcommits.org/en/v1.0.0/) for readable commit histories for humans, tools and LLMs.

Sign commits with GPG, SSH, or S/MIME; GitHub enforces this when merging pull requests.
Read more about [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

To communicate with contributors, use GitHub's assignee field. Check if assigned, then comment that you're working on it. If assigned, ask if they're still active if it's been awhile.

## Coding Conventions

Use `just` for the preferred workflow. If not installed, [installation page](https://just.systems/man/en/packages.html).

Run `just fmt` to format code.
Run `just check` to apply linters and ensure signed commits.
Run `just pre-push` or `just p` before PRs to verify formatting, no linter warnings, passing tests, and signed commits.

Document all public items. Adhere to [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) for documentation.

Carefully consider using `clone`, `unwrap`, or `expect`.

The library uses safe Rust. Avoid `unsafe` blocks.

Add dependencies only if strictly necessary and impossible otherwise.

## Deprecation policy

Avoid breaking existing APIs where possible. Add new APIs and use [`#[deprecated]`](https://GitHub.com/rust-lang/rfcs/blob/master/text/1270-deprecation.md) to discourage old ones.

Maintain deprecated APIs for one release cycle. For example, an API deprecated in 0.10 may be removed in 0.11. This enables smooth upgrades without excessive technical debt.

If you deprecate an API, own it and submit a follow-up PR to remove it in the next cycle.

## Peer review

Anyone can participate in peer review via pull request comments. Reviewers check for obvious errors, test patches, and assess technical merits. Review PRs conceptually first, before code style or grammar fixes.

## Security

Security is a high priority for `bdk-sp` to prevent user fund loss. Since not production-ready, report vulnerabilities via GitHub issues.

## Testing

`bdk-sp` developers prioritize testing seriously. The modular structure makes writing functional tests easy, with good codebase coverage as a key goal.

Test all new features. Make tests unique and self-describing. If ignoring a test, provide a reason with the `#[ignore]` attribute.

Namespace unit tests in an inner module named after the function under test, without `test_` prefix or the function name. The test name should explicitly state the case.

As in [Coding Conventions](#coding-conventions), use `just` to run unit tests, functional tests, integration tests, and doctests:

```bash
just test
```

## Going further

Consider Jon Atack's guides on [How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md) and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md). Despite project differences in context and maturity, many suggestions apply here.

[^1]: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
[^2]: https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki
[^3]: https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
[^4]: https://github.com/setavenger/BIP0352-light-client-specification
