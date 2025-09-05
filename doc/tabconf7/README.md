# TABConf7: Adding Silent Payments Support to BDK

> Workshop prepared to showcase advances in the integration of silent payments into BDK

This workshop is prepared to run on Bitcoin Signet as well as Regtest.

It is also packaged in three different formats depending on your local setup.

Each format has its own playbook, a shell script intended to be executed by copying commands from the file to the shell, but it can also be executed directly:
- [`signet_playbook.sh`](./signet_playbook.sh)
- [`regtest_playbook.sh`](./regtest_playbook.sh)
- [`non_nix_playbook.sh`](./non_nix_playbook.sh)

`signet_playbook.sh` as well as `regtest_playbook.sh` require you to have `nix` on your PATH. The easiest way of installing it on your system is by following:
[https://determinate.systems/nix-installer/](https://determinate.systems/nix-installer/)

`non_nix_playbook.sh`, as its name implies, does not use `nix`, so you will need to install the dependencies of the workshop yourself. These dependencies are:
- [Rust toolchain](https://rustup.rs/)
- [just](https://just.systems/man/en/packages.html)
- [podman](https://podman.io/docs/installation)

Once you have the dependencies for the playbook installed, you are ready to follow the workshop.

All playbooks have numbered steps grouped by stage. There are 6 stages in total:

1. **Setup**
2. **Initial funding**
3. **Creating silent payment outputs**
4. **Funding a transaction with a silent payment output**
5. **Verifying a silent payment change output**
6. **Spending silent payment outputs**

If you're planning to follow the workshop live, note that network connections are not great in crowded places and installation steps may have a large dependency surface; execute stage 1 prior to attending.

If you have executed `stage 1` before participating in the workshop, but on-site you have network issues and can't connect properly to Bitcoin Signet, don't worry! Choose either `regtest_playbook.sh` or `non_nix_playbook.sh` (both run on regtest).

The presentation is divided into the same stages, but do not execute the commands from the presentation blindly! At each stage, listen to the details of the presentation, but stick to the steps in the playbook of your choice.

Happy workshop!
