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

use std::marker::PhantomData;
use snarkvm_circuit_types::Boolean;
use snarkvm_circuit_types::prelude::Environment;
use crate::Hash;

/// The RIPEMD-160 hash.
/// Source: https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
pub struct Ripemd160<E: Environment> {
    phantom_data: PhantomData<E>
}

impl<E: Environment> Ripemd160<E> {
    /// Initializes a new RIPEMD-160 hash.
    pub fn new() -> Self {
        Self { phantom_data : PhantomData}
    }
}
