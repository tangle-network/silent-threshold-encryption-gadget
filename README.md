# Silent Threshold Encryption

This repository implements [silent-threshold-encryption](https://github.com/webb-tools/silent-threshold-encryption-gadget), a threshold encryption/decryption scheme built using [Arkworks](https://arkworks.rs). The scheme allows for a silent setup, which means that parties do not need to communicate interactively. Parties simply generate and upload a public key to a bulletin board (i.e. the [Tangle blockchain](https://github.com/webb-tools/tangle)), and users can encrypt messages to any groups of parties by aggregating these public keys together. Threshold decryptions are performed by a subset of parties, and the scheme guarantees that the decryption is correct if and only if the threshold of parties participate.

## Getting Started
### Preqrequisits
First install and configure `rustup`:

```bash
# Install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Configure
source ~/.cargo/env
```
### Execution
1. To build the project, run:
```bash
RUSTFLAGS="--cfg tokio_unstable" cargo b -r
```
2. To test the project, run:
```bash
RUSTFLAGS="--cfg tokio_unstable" cargo t -r
```
