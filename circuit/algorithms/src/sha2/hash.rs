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

use super::*;

impl<E: Environment, const VARIANT: usize> Hash for Sha2<E, VARIANT> {
    type Input = Boolean<E>;
    type Output = Vec<Boolean<E>>;

    #[inline]
    fn hash(&self, input: &[Self::Input]) -> Self::Output {
        if input.is_empty() {
            return E::halt("The input to the SHA-2 hash function must not be empty");
        }
        let mut bits = pad_sha2(input);
        let chunks = bits.chunks(CHUNK_SIZE);
        let mut state = self.initial_state.clone();

        for chunk in chunks {
            // Message schedule array with zero initialization using std::array::from_fn.
            let mut w: [U32<E>; NUM_ROUNDS] = std::array::from_fn(|_| U32::constant(console::U32::new(0)));
            for t in 0..16 {
                let slice = &chunk[t * WORD_SIZE..(t + 1) * WORD_SIZE];
                w[t] = U32::from_bits_be(slice);
            }
            for t in 16..NUM_ROUNDS {
                let s0 = rotate_right(&w[t - 15], 7)
                    ^ rotate_right(&w[t - 15], 18)
                    ^ shift_right(&w[t - 15], 3);
                let s1 = rotate_right(&w[t - 2], 17)
                    ^ rotate_right(&w[t - 2], 19)
                    ^ shift_right(&w[t - 2], 10);
                w[t] = &(&(&w[t - 16] + &s0) + &w[t - 7]) + &s1;
            }

            let mut a = state[0].clone();
            let mut b = state[1].clone();
            let mut c = state[2].clone();
            let mut d = state[3].clone();
            let mut e = state[4].clone();
            let mut f = state[5].clone();
            let mut g = state[6].clone();
            let mut h = state[7].clone();

            for t in 0..NUM_ROUNDS {
                let S1 = rotate_right(&e, 6)
                    ^ rotate_right(&e, 11)
                    ^ rotate_right(&e, 25);
                let ch = (&e & &f) ^ ((!&e) & &g);
                let temp1 = &(&(&(&h + &S1) + &ch) + &self.constants[t]) + &w[t];
                let S0 = rotate_right(&a, 2)
                    ^ rotate_right(&a, 13)
                    ^ rotate_right(&a, 22);
                let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
                let temp2 = &S0 + &maj;

                h = g;
                g = f;
                f = e;
                e = &d + &temp1;
                d = c;
                c = b;
                b = a;
                a = &temp1 + &temp2;
            }

            for i in 0..8 {
                state[i] = &state[i] + &[a.clone(), b.clone(), c.clone(), d.clone(), e.clone(), f.clone(), g.clone(), h.clone()][i];
            }
        }

        let mut output = Vec::with_capacity(VARIANT);
        for word in state.iter() {
            output.extend(word.to_bits_be());
        }
        output.truncate(VARIANT);
        output
    }
}

fn pad_sha2<E: Environment>(input: &[Boolean<E>]) -> Vec<Boolean<E>> {
    let mut padded = input.to_vec();
    padded.push(Boolean::constant(true));
    while (padded.len() + 64) % CHUNK_SIZE != 0 {
        padded.push(Boolean::constant(false));
    }
    let len_bytes = (input.len() as u64).to_be_bytes();
    for byte in len_bytes.iter() {
        for i in (0..8).rev() {
            padded.push(Boolean::constant((byte >> i) & 1 == 1));
        }
    }
    padded
}

fn rotate_right<E: Environment>(value: &U32<E>, n: usize) -> U32<E> {
    let mut bits = value.to_bits_be();
    bits.rotate_right(n);
    U32::from_bits_be(&bits)
}

fn shift_right<E: Environment>(value: &U32<E>, n: usize) -> U32<E> {
    let mut bits = value.to_bits_be();
    for _ in 0..n {
        bits.insert(0, Boolean::constant(false));
        bits.pop();
    }
    U32::from_bits_be(&bits)
}
