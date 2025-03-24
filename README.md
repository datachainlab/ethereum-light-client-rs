# ethereum-light-client-rs

[![test](https://github.com/datachainlab/ethereum-light-client-rs/actions/workflows/test.yml/badge.svg)](https://github.com/datachainlab/ethereum-light-client-rs/actions/workflows/test.yml)

A rust implementation of the ethereum light client that supports `no_std`.

It currently supports the verification of [Sync Protocol](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md), also called Altair Light Client.

## Key Features

- Sync Protocol verification
    - Supported Forks: Bellatrix, Capella, Deneb, Electra
- Support the detection of Sync committee's misbehaviour
- `no_std` support: easy to integrate into any environment(e.g. wasm, sgx enclave)

## Crates

- [light-client-verifier](./crates/light-client-verifier): provides a Sync Protocol and Execution layer verifiers
- [consensus](./crates/consensus): provides the implementation of [the consensus specs](https://github.com/ethereum/consensus-specs) for beacon chain and sync protocol
- [light-client-cli](./crates/light-client-cli): A toy CLI for Light Client
- [lodestar-rpc](./crates/lodestar-rpc): A RPC client for [lodestar](https://github.com/chainSafe/lodestar)

## Security Audit

We have conducted a security audit of the light client verifier and the consensus crate by [Quantstamp](https://quantstamp.com/). The audit was performed on the codebase of the `light-client-verifier` and `consensus` crates, which are responsible for verifying the Sync Protocol and the execution layer.

The audit report is available [here](https://certificate.quantstamp.com/full/datachain-elc-for-bridge-ethereum/254fdabd-0bdb-4969-8716-9bb29562c5d6/index.html).
