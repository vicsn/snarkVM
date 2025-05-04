// Copyright (c) 2019-2025 Provable Inc.
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

mod hash;

#[cfg(all(test, feature = "console"))]
use snarkvm_circuit_types::environment::assert_scope;
#[cfg(test)]
use snarkvm_utilities::{TestRng, Uniform};

use crate::Hash;
use snarkvm_circuit_types::{Boolean, U32, environment::prelude::*};

/// The SHA-2 224 hash function.
pub type Sha2_224<E> = Sha2<E, 224>;
/// The SHA-2 256 hash function.
pub type Sha2_256<E> = Sha2<E, 256>;

const CHUNK_SIZE: usize = 512;
const WORD_SIZE: usize = 32;
const NUM_ROUNDS: usize = 64;

/// The SHA-2 hash function.
#[derive(Clone, Debug)]
pub struct Sha2<E: Environment, const VARIANT: usize> {
    /// Round constants.
    constants: [U32<E>; NUM_ROUNDS],
    /// Initial hash state.
    initial_state: [U32<E>; 8],
}

impl<E: Environment, const VARIANT: usize> Sha2<E, VARIANT> {
    /// Initializes a new SHA-2 hash function.
    pub fn new() -> Self {
        // Initialize round constants using std::array::from_fn.
        let constants = std::array::from_fn(|i| U32::constant(console::U32::new(K[i])));
        // Initialize initial state depending on variant (224 or 256).
        let initial_state = match VARIANT {
            256 => std::array::from_fn(|i| U32::constant(console::U32::new(H0_256[i]))),
            224 => std::array::from_fn(|i| U32::constant(console::U32::new(H0_224[i]))),
            _ => unreachable!("Invalid SHA-2 variant"),
        };
        Self { constants, initial_state }
    }
}

// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
const K: [u32; NUM_ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const H0_224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];