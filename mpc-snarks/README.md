# snarkvm-mpc-snarks

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

This implementation is based off of the code accompanying the paper that introduced
Collaborative zkSNARKs: "Experimenting with Collaborative zk-SNARKs: Zero-Knowledge 
Proofs for Distributed Secrets".

## Running E2E test

1. Enter `mpc-snarks`.
2. `cargo +nightly build --bin mpc-test`.
3. `./scripts/bench.zsh marlin spdz 10 2`.

## Open TODOs
- [ ] Currently, `mask_poly` is secret-shared in a late stage using a hacky `share_from_public`. It should be possible to directly sample into the correct type.
- [ ] Generalize `king_share` to allow secret-sharing data from any `party_id`.
- [ ] Review security comprehensively. In particular, currently all randomness, including the masking polynomial, is sampled publicly (i.e. known by all parties in the MPC) and from a fixed seed. Excess data is currently returned and revealed from the proof system just for testing purposes.
- [ ] Build support in snarkVM and Leo compiler to prove arbitrary Executions in MPC. In particular, this requires language features which allow a developer to specify which program inputs, e.g. foreign records, are created by which user. Note that support for arbitrary sharing of inputs requires building out snarkVM compiler logic in MPC.
- [ ] The current `reveal` logic, when used to reveal containers, can create subtle bugs when the containers of all parties are not equally long. Some kind of length check should be embedded.
- [ ] POWERS_OF_ROOTS_OF_UNITY should be a compile-time constant (using static lifetime references)