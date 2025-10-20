# TABConf7: Adding Silent Payments Support to BDK

> [!CAUTION]
> This workshop has been prepared for educative purposes. Only runs on bitcoin signet or regtest. Do not try to run it on bitcoin mainnet.

## Organization

> [!TIP]
> Execute the `stage 1` of your preferred playbook before participating of the workshop. Installation of dependencies takes time and depends of connectivity.

The workshop has been packaged in different playbooks depending on your local setup and level of expertise with shell tools.

The presentation as well as the playbooks has been structured semantically by numbered stages. The same stage achieves the same outcome on each different playbook and in the presentation. There are 7 in total:

1. **Setup**
2. **Fund bdk-cli wallet**
3. **Create a silent payment output**
4. **Find a silent payment output**
5. **Fund a transaction with a silent payment output**
6. **Verify a silent payment change output**
7. **Spend a silent payment output**

Each stage is composed of multiple steps, all numbered, to ensure execution order.
All seps are documented with an accompanying comment.

> [!IMPORTANT]
> If you are following this workshop live, do not execute the commands you see on the presentation blindly!
> Follow the presentation through stages, but stick to the steps in the playbook of your choice.

## Playbooks

> [!TIP]
> Do not use `chmod +x script.sh && ./script.sh` to execute `signet_playbook.sh`, `regtest_playbook.sh` nor `non_nix_playbook.sh`. It will work, but is easier to debug during workshop if you execute each command separately.

There are three intended to be executed by **copying commands** from the file to the shell:

##### [`signet_playbook.sh`](./signet_playbook.sh)
###### Requirements:
- **nix**, the easiest way of installing it on your system is by following: [https://determinate.systems/nix-installer/](https://determinate.systems/nix-installer/).

##### [`regtest_playbook.sh`](./regtest_playbook.sh)
###### Requirements:
- **nix**, the easiest way of installing it on your system is by following: [https://determinate.systems/nix-installer/](https://determinate.systems/nix-installer/).

##### [`non_nix_playbook.sh`](./non_nix_playbook.sh)
###### Requirements:
- [podman](https://podman.io/docs/installation)
- [rust toolchain](https://rustup.rs/)
- [just](https://just.systems/man/en/packages.html)

##### [`auto_playbook.sh`](./auto_playbook.sh)

Based on [`non_nix_playbook.sh`](./non_nix_playbook.sh), directed for users not familiar with the shell, that also want to participate of the workshop.

> [!NOTE]
> This playbook is different to the previous ones.
> It only requires you to execute it with `chmod +x auto_playbook.sh && ./auto_playbook.sh` and pressing enter as instructed by the script itself.

###### Requirements:
- [podman](https://podman.io/docs/installation)
- [rust toolchain](https://rustup.rs/)
- [just](https://just.systems/man/en/packages.html)

Once you have the dependencies for the playbook installed, you are ready to follow the workshop.

Happy workshop!

## FAQ

<details>

<summary>How to choose what playbook to follow?</summary>

First, try to install `nix` and execute `stage 1` of [`signet_playbook.sh`](./signet_playbook.sh). If [`nix`](https://determinate.systems/nix-installer/) is taking too long, you have issues due to your architecture or any other error you cannot figure out how to fix, try installing [`podman`](https://podman.io/docs/installation) with their indicated method for your machine, and proceed to execute `stage 1` of [`non_nix_playbook.sh`](./non_nix_playbook.sh). Please, fill an [issue](https://github.com/bitcoindevkit/bdk-sp/issues/new/choose) documenting the error on the repository to try to find a fix and improve this **FAQ**.

</details>

<details>

<summary>On which network is the workshop running?</summary>

If you choose [`signet_playbook.sh`](./signet_playbook.sh), you will be working with `signet`. If you choose [`regtest_playbook.sh`](./regtest_playbook.sh), [`non_nix_playbook.sh`](./non_nix_playbook.sh) or [`auto_playbook.sh`](./auto_playbook.sh) you will be working on `regtest`. There is no playbook for `testnet3`, `testnet4` nor `mainnet`.

</details>

<details>

<summary>Signet is taking too long, what can I do?</summary>

Choose any of the `regtest` playbooks working on your machine and follow the commands there.

</details>
