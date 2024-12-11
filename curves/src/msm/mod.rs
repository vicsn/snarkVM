// Copyright 2024 Aleo Network Foundation
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

pub mod fixed_base;
pub use fixed_base::*;

#[cfg(test)]
pub mod tests;

pub mod variable_base;
pub use variable_base::*;

/// Returns the ceiling of the base-2 logarithm of `x`.
///
/// ```
/// use snarkvm_fft::fft::domain::log2;
///
/// assert_eq!(log2(16), 4);
/// assert_eq!(log2(17), 5);
/// assert_eq!(log2(1), 0);
/// assert_eq!(log2(0), 0);
/// assert_eq!(log2(usize::MAX), (core::mem::size_of::<usize>() * 8) as u32);
/// assert_eq!(log2(1 << 15), 15);
/// assert_eq!(log2(2usize.pow(18)), 18);
/// ```
pub fn log2(x: usize) -> u32 { // TODO: duplicate with snarkvm_fft::fft::domain::log2
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

/// The result of this function is only approximately `ln(a)`
/// [`Explanation of usage`]
///
/// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (log2(a) * 69 / 100) as usize
}
