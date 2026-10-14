// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

use circuit::{Aleo as _, Environment, environment::compare_constraints};
use console::program::{
    BlockPath,
    BlockTree,
    HeaderLeaf,
    HeaderPath,
    HeaderTree,
    Plaintext,
    Record,
    TransactionPath,
    TransactionTree,
    TransactionsPath,
    TransactionsTree,
    TransitionPath,
    TransitionTree,
};

use crate::tests::test_utils::{CurrentAleo, CurrentNetwork};

/// Replaces the first sibling of the given Merkle path with a random field element.
macro_rules! corrupt_first_sibling {
    ($path:expr, $path_type:ty, $rng:expr) => {{
        let mut siblings = $path.siblings().to_vec();
        siblings[0] = Field::<CurrentNetwork>::rand($rng);
        // Reconstruction cannot fail: the sibling count and leaf index are unchanged.
        $path = <$path_type>::try_from(($path.leaf_index(), siblings))?;
    }};
}

/// The origin of the state path.
///
/// A `Global` path has a valid block linkage, as for a record consumed from a prior block.
/// A `Local` path has a broken block linkage, as for a path constructed via `StatePath::new_local`
/// for a record produced in the current execution. Only the transition and transaction portions
/// of a `Local` path can verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathOrigin {
    /// The block hash is derived from the previous block hash and the header root.
    Global,
    /// The block hash is random, so the global branch of the circuit cannot be satisfied.
    Local,
}

/// The local state root provided as a public input to the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalStateRoot {
    /// Equals the transaction ID of the state path.
    Matching,
    /// A random field element.
    Mismatched,
}

/// The record commitment provided as a private input to the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitmentVariant {
    /// Equals the ID of the transition leaf in the state path.
    TransitionLeafId,
    /// A random field element.
    Mismatched,
}

/// The serial number provided as a public input to the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SerialNumberVariant {
    /// `Commit(commitment || Hash(COFACTOR * gamma))` for the provided commitment and gamma.
    Consistent,
    /// The serial number of the provided commitment under a *different* gamma.
    Mismatched,
}

/// The record block height used by the tests, distinct from the boundary heights. The leaf index
/// of the block path is the record block height read by the circuit, so the sampled block tree
/// proves at this leaf index.
const RECORD_BLOCK_HEIGHT: u32 = 5;

/// The `(record block height, upgrade block height)` pairs used by the input matrix, covering the
/// record block height below, equal to, and above the upgrade block height, and the boundaries
/// of the minimum height and the maximum upgrade height.
const HEIGHTS: [(u32, u32); 5] = [
    (RECORD_BLOCK_HEIGHT, RECORD_BLOCK_HEIGHT + 1), // The record block height is below.
    (RECORD_BLOCK_HEIGHT, RECORD_BLOCK_HEIGHT),     // The record block height is equal.
    (RECORD_BLOCK_HEIGHT, RECORD_BLOCK_HEIGHT - 1), // The record block height is above.
    (0, 0),                                         // The record block height is equal, at zero.
    (0, u32::MAX),                                  // The record block height is below the maximum.
];

/// A single configuration of the inclusion assignment inputs, including an optional state path
/// corruption. Every test case is an `InclusionVariation` checked against `expected_satisfied`.
#[derive(Clone, Copy, Debug)]
struct InclusionVariation {
    /// The origin of the state path.
    origin: PathOrigin,
    /// The `is_global` flag, which selects the state path branch that is verified.
    is_global: bool,
    /// The local state root, which is verified when `is_global` is false.
    local_state_root: LocalStateRoot,
    /// The record commitment, which must match the transition leaf of the state path.
    commitment: CommitmentVariant,
    /// The serial number, which must be consistent with the commitment and gamma.
    serial_number: SerialNumberVariant,
    /// The record block height, which the circuit reads as the block path leaf index.
    record_block_height: u32,
    /// The upgrade block height.
    upgrade_block_height: u32,
    /// The claimed `is_record_block_height_reached` flag.
    is_record_block_height_reached: bool,
    /// The corruption applied to the state path, if any.
    corruption: Option<StatePathCorruption>,
}

/// Samples a state path for the given commitment, whose block path proves the block hash at
/// leaf index `record_block_height`.
///
/// This mirrors `console::program::state_path::test_helpers`, with two differences:
/// - the block tree contains `record_block_height` leading random leaves, so that the proven
///   leaf index (and thus the record block height read by the circuit) is `record_block_height`;
/// - for a `PathOrigin::Local` path, the block hash is random, which breaks the block linkage.
fn sample_state_path(
    origin: PathOrigin,
    commitment: Field<CurrentNetwork>,
    record_block_height: u32,
    rng: &mut TestRng,
) -> Result<StatePath<CurrentNetwork>> {
    // Prepare the tcm.
    let tcm = Field::rand(rng);

    // Construct the transition path and transition leaf.
    let transition_leaf = TransitionLeaf::new(0, 3, commitment);
    let transition_tree: TransitionTree<CurrentNetwork> =
        CurrentNetwork::merkle_tree_bhp(&[transition_leaf.to_bits_le()])?;
    let transition_root = *transition_tree.root();
    let transition_leaf_id = CurrentNetwork::hash_bhp512(&(transition_root, tcm).to_bits_le())?;
    let transition_path = transition_tree.prove(0, &transition_leaf.to_bits_le())?;

    // Construct the transaction path and transaction leaf.
    let transaction_leaf = TransactionLeaf::new_execution(0, transition_leaf_id);
    let transaction_tree: TransactionTree<CurrentNetwork> =
        CurrentNetwork::merkle_tree_bhp(&[transaction_leaf.to_bits_le()])?;
    let transaction_id = *transaction_tree.root();
    let transaction_path = transaction_tree.prove(0, &transaction_leaf.to_bits_le())?;

    // Construct the transactions path.
    let transactions_tree: TransactionsTree<CurrentNetwork> =
        CurrentNetwork::merkle_tree_bhp(&[transaction_id.to_bits_le()])?;
    let transactions_root = *transactions_tree.root();
    let transactions_path = transactions_tree.prove(0, &transaction_id.to_bits_le())?;

    // Construct the block header path. The header leaf index 1 is `Header::transactions_root`.
    let header_leaf = HeaderLeaf::new(1, transactions_root);
    let header_tree: HeaderTree<CurrentNetwork> =
        CurrentNetwork::merkle_tree_bhp(&[Field::<CurrentNetwork>::zero().to_bits_le(), header_leaf.to_bits_le()])?;
    let header_root = *header_tree.root();
    let header_path = header_tree.prove(1, &header_leaf.to_bits_le())?;

    // Construct the block hash.
    let previous_block_hash: <CurrentNetwork as Network>::BlockHash = Field::<CurrentNetwork>::rand(rng).into();
    let block_hash = match origin {
        // The block hash is the hash of the previous block hash and the header root.
        PathOrigin::Global => CurrentNetwork::hash_bhp1024(
            &(*previous_block_hash).to_bits_le().into_iter().chain(header_root.to_bits_le()).collect::<Vec<_>>(),
        )?,
        // A random block hash breaks the block linkage, so the global branch cannot be satisfied.
        PathOrigin::Local => Field::rand(rng),
    };

    // Construct the global state root and block path.
    let block_leaves = (0..record_block_height)
        .map(|_| Field::<CurrentNetwork>::rand(rng).to_bits_le())
        .chain([block_hash.to_bits_le()])
        .collect::<Vec<_>>();
    let block_tree: BlockTree<CurrentNetwork> = CurrentNetwork::merkle_tree_bhp(&block_leaves)?;
    let global_state_root = *block_tree.root();
    let block_path = block_tree.prove(record_block_height as usize, &block_hash.to_bits_le())?;

    Ok(StatePath::from(
        global_state_root.into(),
        block_path,
        block_hash.into(),
        previous_block_hash,
        header_root,
        header_path,
        header_leaf,
        transactions_path,
        transaction_id.into(),
        transaction_path,
        transaction_leaf,
        transition_root,
        tcm,
        transition_path,
        transition_leaf,
    ))
}

/// The deconstructed components of a state path, used to rebuild paths with corrupted components.
struct StatePathParts {
    global_state_root: <CurrentNetwork as Network>::StateRoot,
    block_path: BlockPath<CurrentNetwork>,
    block_hash: <CurrentNetwork as Network>::BlockHash,
    previous_block_hash: <CurrentNetwork as Network>::BlockHash,
    header_root: Field<CurrentNetwork>,
    header_path: HeaderPath<CurrentNetwork>,
    header_leaf: HeaderLeaf<CurrentNetwork>,
    transactions_path: TransactionsPath<CurrentNetwork>,
    transaction_id: <CurrentNetwork as Network>::TransactionID,
    transaction_path: TransactionPath<CurrentNetwork>,
    transaction_leaf: TransactionLeaf<CurrentNetwork>,
    transition_root: Field<CurrentNetwork>,
    tcm: Field<CurrentNetwork>,
    transition_path: TransitionPath<CurrentNetwork>,
    transition_leaf: TransitionLeaf<CurrentNetwork>,
}

impl StatePathParts {
    /// Deconstructs the given state path into its components.
    fn new(path: &StatePath<CurrentNetwork>) -> Self {
        Self {
            global_state_root: path.global_state_root(),
            block_path: path.block_path().clone(),
            block_hash: path.block_hash(),
            previous_block_hash: path.previous_block_hash(),
            header_root: *path.header_root(),
            header_path: path.header_path().clone(),
            header_leaf: *path.header_leaf(),
            transactions_path: path.transactions_path().clone(),
            transaction_id: *path.transaction_id(),
            transaction_path: path.transaction_path().clone(),
            transaction_leaf: *path.transaction_leaf(),
            transition_root: *path.transition_root(),
            tcm: *path.tcm(),
            transition_path: path.transition_path().clone(),
            transition_leaf: *path.transition_leaf(),
        }
    }

    /// Reconstructs a state path from the components.
    fn rebuild(self) -> StatePath<CurrentNetwork> {
        StatePath::from(
            self.global_state_root,
            self.block_path,
            self.block_hash,
            self.previous_block_hash,
            self.header_root,
            self.header_path,
            self.header_leaf,
            self.transactions_path,
            self.transaction_id,
            self.transaction_path,
            self.transaction_leaf,
            self.transition_root,
            self.tcm,
            self.transition_path,
            self.transition_leaf,
        )
    }
}

/// A named corruption of a state path component.
#[derive(Clone, Copy, Debug)]
struct StatePathCorruption {
    /// The name of the corrupted component.
    name: &'static str,
    /// Whether the corrupted component is verified in the local branch of the circuit.
    /// The transition and transaction portions are verified in *both* branches.
    is_verified_in_local_branch: bool,
    /// Applies the corruption to the deconstructed state path.
    apply: fn(&mut StatePathParts, &mut TestRng) -> Result<()>,
}

/// Returns every state path component corruption exercised by the tests.
fn state_path_corruptions() -> [StatePathCorruption; 16] {
    [
        // Corruptions of components that only the global branch verifies.
        StatePathCorruption {
            name: "random global state root",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                parts.global_state_root = Field::<CurrentNetwork>::rand(rng).into();
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random block hash",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                parts.block_hash = Field::<CurrentNetwork>::rand(rng).into();
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random previous block hash",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                parts.previous_block_hash = Field::<CurrentNetwork>::rand(rng).into();
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random header root",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                parts.header_root = Field::rand(rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random header leaf ID",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                parts.header_leaf = HeaderLeaf::new(1, Field::rand(rng));
                Ok(())
            },
        },
        StatePathCorruption {
            name: "header leaf index 0 (must be 1)",
            is_verified_in_local_branch: false,
            apply: |parts, _rng| {
                parts.header_leaf = HeaderLeaf::new(0, parts.header_leaf.id());
                Ok(())
            },
        },
        StatePathCorruption {
            name: "corrupted block path sibling",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                corrupt_first_sibling!(parts.block_path, BlockPath<CurrentNetwork>, rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "corrupted header path sibling",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                corrupt_first_sibling!(parts.header_path, HeaderPath<CurrentNetwork>, rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "corrupted transactions path sibling",
            is_verified_in_local_branch: false,
            apply: |parts, rng| {
                corrupt_first_sibling!(parts.transactions_path, TransactionsPath<CurrentNetwork>, rng);
                Ok(())
            },
        },
        // Corruptions of components that both branches verify.
        StatePathCorruption {
            name: "random transaction ID",
            is_verified_in_local_branch: true,
            apply: |parts, rng| {
                parts.transaction_id = Field::<CurrentNetwork>::rand(rng).into();
                Ok(())
            },
        },
        StatePathCorruption {
            name: "transaction leaf variant 2 (must be 1)",
            is_verified_in_local_branch: true,
            apply: |parts, _rng| {
                parts.transaction_leaf =
                    TransactionLeaf::from(2, parts.transaction_leaf.index(), parts.transaction_leaf.id());
                Ok(())
            },
        },
        StatePathCorruption {
            name: "corrupted transaction path sibling",
            is_verified_in_local_branch: true,
            apply: |parts, rng| {
                corrupt_first_sibling!(parts.transaction_path, TransactionPath<CurrentNetwork>, rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random transition root",
            is_verified_in_local_branch: true,
            apply: |parts, rng| {
                parts.transition_root = Field::rand(rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "random tcm",
            is_verified_in_local_branch: true,
            apply: |parts, rng| {
                parts.tcm = Field::rand(rng);
                Ok(())
            },
        },
        StatePathCorruption {
            name: "transition leaf variant 2 (must be 3)",
            is_verified_in_local_branch: true,
            apply: |parts, _rng| {
                parts.transition_leaf =
                    TransitionLeaf::new(parts.transition_leaf.index(), 2, parts.transition_leaf.id());
                Ok(())
            },
        },
        StatePathCorruption {
            name: "corrupted transition path sibling",
            is_verified_in_local_branch: true,
            apply: |parts, rng| {
                corrupt_first_sibling!(parts.transition_path, TransitionPath<CurrentNetwork>, rng);
                Ok(())
            },
        },
    ]
}

/// Samples the inclusion assignment inputs for the given variation, and returns the assignment.
fn sample_case(rng: &mut TestRng, variation: InclusionVariation) -> Result<InclusionAssignment<CurrentNetwork>> {
    // Sample the state path for a random record commitment, and apply the corruption, if any.
    let path_commitment = Field::rand(rng);
    let mut state_path = sample_state_path(variation.origin, path_commitment, variation.record_block_height, rng)?;
    if let Some(corruption) = variation.corruption {
        let mut parts = StatePathParts::new(&state_path);
        (corruption.apply)(&mut parts, rng)?;
        state_path = parts.rebuild();
    }

    // Resolve the commitment variation.
    let commitment = match variation.commitment {
        CommitmentVariant::TransitionLeafId => path_commitment,
        CommitmentVariant::Mismatched => Field::rand(rng),
    };

    // Sample gamma, and resolve the serial number variation.
    let gamma = Group::rand(rng);
    let serial_number_gamma = match variation.serial_number {
        SerialNumberVariant::Consistent => gamma,
        // A serial number under a different gamma is inconsistent with the sampled gamma.
        SerialNumberVariant::Mismatched => Group::rand(rng),
    };
    let serial_number = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number_from_gamma(
        &serial_number_gamma,
        commitment,
    )?;

    // Resolve the local state root variation, which matches the (possibly corrupted) transaction ID.
    let local_state_root = match variation.local_state_root {
        LocalStateRoot::Matching => *state_path.transaction_id(),
        LocalStateRoot::Mismatched => Field::<CurrentNetwork>::rand(rng).into(),
    };

    Ok(InclusionAssignment::<CurrentNetwork>::new(
        state_path,
        commitment,
        gamma,
        serial_number,
        variation.is_record_block_height_reached,
        variation.upgrade_block_height,
        local_state_root,
        variation.is_global,
    ))
}

/// Returns whether the inclusion circuit is expected to be satisfied for the given variation,
/// modeling the four assertions of `InclusionAssignment::to_circuit_assignment`:
///
/// 1. The commitment equals the transition leaf ID of the state path.
/// 2. The serial number equals `Commit(commitment || Hash(COFACTOR * gamma))`.
/// 3. The state path verifies:
///    - if `is_global` is true, the entire path up to the global state root must verify (only a
///      `PathOrigin::Global` path has a valid block linkage, and no component may be corrupted;
///      the local state root is not consulted);
///    - if `is_global` is false, the transaction ID of the path must equal the local state root,
///      and only the transition and transaction portions may not be corrupted.
/// 4. The height check is enforced only if `is_global` is true:
///    `is_record_block_height_reached == (record_block_height >= upgrade_block_height)`.
fn expected_satisfied(variation: InclusionVariation) -> bool {
    // The commitment matches the transition leaf of the state path.
    let commitment_ok = variation.commitment == CommitmentVariant::TransitionLeafId;
    // The serial number is derived from the given commitment and gamma.
    let serial_number_ok = variation.serial_number == SerialNumberVariant::Consistent;
    // The state path verifies against the selected root.
    let state_path_ok = match variation.is_global {
        true => variation.origin == PathOrigin::Global && variation.corruption.is_none(),
        false => {
            variation.local_state_root == LocalStateRoot::Matching
                && variation.corruption.is_none_or(|corruption| !corruption.is_verified_in_local_branch)
        }
    };
    // The height check is enforced only for global state paths.
    let is_record_at_or_past_upgrade = variation.record_block_height >= variation.upgrade_block_height;
    let height_ok = !variation.is_global || (variation.is_record_block_height_reached == is_record_at_or_past_upgrade);
    commitment_ok && serial_number_ok && state_path_ok && height_ok
}

/// Synthesizes the inclusion circuit for the given variation, resets the circuit environment, and
/// checks that the circuit satisfaction matches `expected_satisfied`.
fn check_variation(rng: &mut TestRng, variation: InclusionVariation) -> Result<()> {
    let assignment = sample_case(rng, variation)?;
    assignment.to_circuit_assignment_internal::<CurrentAleo>()?;
    let satisfied = CurrentAleo::is_satisfied();
    CurrentAleo::reset();
    let corruption = variation.corruption.map_or("none", |corruption| corruption.name);
    assert_eq!(satisfied, expected_satisfied(variation), "corruption: {corruption}, variation: {variation:?}");
    Ok(())
}

/// Checks every combination of the input variations: the state path origin, the `is_global` flag,
/// the local state root, the record commitment, the serial number, the record and upgrade block
/// heights, and the claimed `is_record_block_height_reached` flag.
/// This is 2 * 2 * 2 * 2 * 2 * 5 * 2 = 320 combinations, positive and negative.
fn check_input_matrix(rng: &mut TestRng) -> Result<()> {
    for origin in [PathOrigin::Global, PathOrigin::Local] {
        for is_global in [true, false] {
            for local_state_root in [LocalStateRoot::Matching, LocalStateRoot::Mismatched] {
                for commitment in [CommitmentVariant::TransitionLeafId, CommitmentVariant::Mismatched] {
                    for serial_number in [SerialNumberVariant::Consistent, SerialNumberVariant::Mismatched] {
                        for (record_block_height, upgrade_block_height) in HEIGHTS {
                            for is_record_block_height_reached in [true, false] {
                                check_variation(rng, InclusionVariation {
                                    origin,
                                    is_global,
                                    local_state_root,
                                    commitment,
                                    serial_number,
                                    record_block_height,
                                    upgrade_block_height,
                                    is_record_block_height_reached,
                                    corruption: None,
                                })?;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Checks every state path component corruption in both circuit branches, with all other inputs
/// valid: the height check passes, and the local state root matches the corrupted transaction ID.
fn check_corrupted_state_paths(rng: &mut TestRng) -> Result<()> {
    for corruption in state_path_corruptions() {
        for is_global in [true, false] {
            check_variation(rng, InclusionVariation {
                origin: PathOrigin::Global,
                is_global,
                local_state_root: LocalStateRoot::Matching,
                commitment: CommitmentVariant::TransitionLeafId,
                serial_number: SerialNumberVariant::Consistent,
                record_block_height: RECORD_BLOCK_HEIGHT,
                upgrade_block_height: RECORD_BLOCK_HEIGHT,
                is_record_block_height_reached: true,
                corruption: Some(corruption),
            })?;
        }
    }
    Ok(())
}

/// Checks that the inclusion circuit structure is independent of the assignment values, so that
/// a single (universal) proving key covers every inclusion proof.
fn check_structure_invariance(rng: &mut TestRng) -> Result<()> {
    // Representative variations covering every dimension of the input matrix.
    let variations = [
        InclusionVariation {
            origin: PathOrigin::Global,
            is_global: true,
            local_state_root: LocalStateRoot::Matching,
            commitment: CommitmentVariant::TransitionLeafId,
            serial_number: SerialNumberVariant::Consistent,
            record_block_height: RECORD_BLOCK_HEIGHT,
            upgrade_block_height: RECORD_BLOCK_HEIGHT,
            is_record_block_height_reached: true,
            corruption: None,
        },
        InclusionVariation {
            origin: PathOrigin::Local,
            is_global: false,
            local_state_root: LocalStateRoot::Matching,
            commitment: CommitmentVariant::TransitionLeafId,
            serial_number: SerialNumberVariant::Consistent,
            record_block_height: RECORD_BLOCK_HEIGHT,
            upgrade_block_height: RECORD_BLOCK_HEIGHT + 1,
            is_record_block_height_reached: false,
            corruption: None,
        },
        InclusionVariation {
            origin: PathOrigin::Global,
            is_global: false,
            local_state_root: LocalStateRoot::Mismatched,
            commitment: CommitmentVariant::Mismatched,
            serial_number: SerialNumberVariant::Mismatched,
            record_block_height: RECORD_BLOCK_HEIGHT,
            upgrade_block_height: RECORD_BLOCK_HEIGHT - 1,
            is_record_block_height_reached: true,
            corruption: None,
        },
        InclusionVariation {
            origin: PathOrigin::Local,
            is_global: true,
            local_state_root: LocalStateRoot::Mismatched,
            commitment: CommitmentVariant::TransitionLeafId,
            serial_number: SerialNumberVariant::Consistent,
            record_block_height: 0,
            upgrade_block_height: u32::MAX,
            is_record_block_height_reached: false,
            corruption: None,
        },
    ];

    // Synthesize each variation, and collect the ejected assignments.
    let assignments = variations
        .iter()
        .map(|variation| sample_case(rng, *variation)?.to_circuit_assignment::<CurrentAleo>())
        .collect::<Result<Vec<_>>>()?;

    // Ensure every assignment has an identical constraint structure.
    for assignment in assignments.iter().skip(1) {
        compare_constraints(&assignments[0], assignment)?;
    }
    Ok(())
}

/// Runs every inclusion circuit case from a single entry point:
///
/// - `check_input_matrix`: every combination of the input variations, positive and negative;
/// - `check_corrupted_state_paths`: every state path component corruption, in both branches;
/// - `check_structure_invariance`: the circuit structure is identical across the variations.
#[test]
fn test_inclusion_assignment() -> Result<()> {
    CurrentAleo::initialize_global_constants();
    // Initializing the global constants pollutes the current circuit with constant variables,
    // so reset the circuit environment afterwards (as in `TranslationAssignment`).
    CurrentAleo::reset();
    let rng = &mut TestRng::fixed(1_031_249);

    check_input_matrix(rng)?;
    check_corrupted_state_paths(rng)?;
    check_structure_invariance(rng)?;
    Ok(())
}
