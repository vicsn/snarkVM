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

    /// Apply SHA-224 or SHA-256 to the input bits.
    /// The bits do not have to be padded; this function does that.
    // TODO: probably don't inline?
    #[inline]
    fn hash(&self, input: &[Self::Input]) -> Self::Output {

        // Checking this is likely overkill, but it is the documented limit on message size.
        // See FIPS PUB 180-4, Figure 1.
        if input.len() as u128 >= 2u128.pow(64) {
            // TODO: don't panic and handle the error more gracefully
            panic!("Input to SHA-224 or SHA-256 must be less than 2^64 bits");
        }
        // Note that an empty input is valid and allowed.

        let bits = pad_sha2(input);
        let chunks = bits.chunks(BLOCK_SIZE);

        let constants: [U32<E>; 64] = std::array::from_fn(|i| U32::constant(console::U32::new(K[i])));

        // This is the current hash, initially `H^(0)`, eventually `H^(N)` (see FIPS PUB 180-4, Section 6.2).
        let mut state: [U32<E>; 8] = match VARIANT {
            256 => std::array::from_fn(|i| U32::constant(console::U32::new(H0_256[i]))),
            224 => std::array::from_fn(|i| U32::constant(console::U32::new(H0_224[i]))),
            _ => unreachable!("Invalid SHA-2 variant"),
        };

        // This loop corresponds to the top-level loop 'For i = 1 to N' in FIPS PUB 180-4, Section 6.2.2.
        for chunk in chunks {

            // Step 1 in FIPS PUB 180-4 Section 6.2.2.
            // TODO: should we avoid the circuit constants in the initialization of the array?
            let mut w: [U32<E>; NUM_ROUNDS] = std::array::from_fn(|_| U32::constant(console::U32::new(0)));
            for t in 0..16 {
                let slice = &chunk[t * WORD_SIZE..(t + 1) * WORD_SIZE];
                w[t] = U32::from_bits_be(slice);
            }
            for t in 16..NUM_ROUNDS {
                // sigma_0(W_t-15):
                let s0 = rotate_right(&w[t - 15], 7) ^ rotate_right(&w[t - 15], 18) ^ shift_right(&w[t - 15], 3);
                // sigma_1(W_t-2):
                let s1 = rotate_right(&w[t - 2], 17) ^ rotate_right(&w[t - 2], 19) ^ shift_right(&w[t - 2], 10);
                w[t] = s1.add_wrapped(&w[t - 7]).add_wrapped(&s0).add_wrapped(&w[t - 16]);
            }

            // Step 2 in FIPS PUB 180-4, Section 6.2.2.
            let mut a = state[0].clone();
            let mut b = state[1].clone();
            let mut c = state[2].clone();
            let mut d = state[3].clone();
            let mut e = state[4].clone();
            let mut f = state[5].clone();
            let mut g = state[6].clone();
            let mut h = state[7].clone();

            // Step 3 in FIPS PUB 180-4, Section 6.2.2.
            for t in 0..NUM_ROUNDS {
                // Sigma_1(e):
                let S1 = rotate_right(&e, 6) ^ rotate_right(&e, 11) ^ rotate_right(&e, 25);
                // Ch(e, f, g):
                let ch = (&e & &f) ^ ((!&e) & &g);
                // T1:
                let temp1 = h.add_wrapped(&S1).add_wrapped(&ch).add_wrapped(&constants[t]).add_wrapped(&w[t]);
                // Sigma_0(a):
                let S0 = rotate_right(&a, 2) ^ rotate_right(&a, 13) ^ rotate_right(&a, 22);
                // Maj(a, b, c):
                let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
                // T2:
                let temp2 = S0.add_wrapped(&maj);

                h = g;
                g = f;
                f = e;
                e = d.add_wrapped(&temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.add_wrapped(&temp2);
            }

            // Step 4 in FIPS PUB 180-4 Section 6.2.2.
            state[0] = a.add_wrapped(&state[0]);
            state[1] = b.add_wrapped(&state[1]);
            state[2] = c.add_wrapped(&state[2]);
            state[3] = d.add_wrapped(&state[3]);
            state[4] = e.add_wrapped(&state[4]);
            state[5] = f.add_wrapped(&state[5]);
            state[6] = g.add_wrapped(&state[6]);
            state[7] = h.add_wrapped(&state[7]);
        }

        // Turn the final has value into a sequence of bits.
        let mut output = Vec::with_capacity(256);
        for word in state.iter() {
            output.extend(word.to_bits_be());
        }

        // Keep and return 256 or 224 bits.
        output.truncate(VARIANT);
        output
    }
}

/// Pad the input bits to a multiple of the block size.
/// See FIPS PUB 180-4, Section 5.1.1.
fn pad_sha2<E: Environment>(input: &[Boolean<E>]) -> Vec<Boolean<E>> {
    let mut padded = input.to_vec();

    // Add a '1' bit.
    padded.push(Boolean::constant(true));

    // Add as many '0' bits as needed to make the length congruent to 448 mod 512,
    // so that there are exactly 64 bits left for the length (448 + 64 = 512).
    while (padded.len() + 64) % BLOCK_SIZE != 0 {
        padded.push(Boolean::constant(false));
    }

    // This cast never fails because we checked the input length in `hash`.
    let len = input.len() as u64;
    // We allocate new circuit variables for the 64 bits of the length because they depend on the input.
    // TODO: perhaps we can allocate constants instead, given that the circuit is for the particular input length
    for i in (0..64).rev() {
        padded.push(Boolean::new(Mode::Private, (len >> i) & 1 == 1));
    }

    // The result has a length that is a multiple of the block size.
    padded
}

/// The `ROTR^n` operation in FIPS PUB 180-4, Section 3.2.
fn rotate_right<E: Environment>(value: &U32<E>, n: usize) -> U32<E> {
    let mut bits = value.to_bits_be();
    bits.rotate_right(n);
    U32::from_bits_be(&bits)
}

/// The `SHR^n` operation in FIPS PUB 180-4, Section 3.2.
fn shift_right<E: Environment>(value: &U32<E>, n: usize) -> U32<E> {
    let mut bits = value.to_bits_be();
    for _ in 0..n {
        bits.insert(0, Boolean::constant(false));
        bits.pop();
    }
    U32::from_bits_be(&bits)
}

#[cfg(test)]
mod tests {
    use snarkvm_circuit_types::{
        Boolean,
        environment::{Circuit, Eject, Inject},
    };
    use crate::{Hash, Sha2_256};

    fn bits_to_hex_string(bits: &[Boolean<Circuit>]) -> String {
        let mut string = String::new();
        for four_bits in bits.chunks(4) {
            let hex_digit = four_bits.iter().fold(0, |acc, bit| (acc << 1) + bit.eject_value() as u8);
            string.push_str(&format!("{:01x}", hex_digit));
        }
        string
    }

    fn string_to_bits(string: &str) -> Vec<Boolean<Circuit>> {
        let mut bits = Vec::new();
        for c in string.chars() {
            let byte = c as u8;
            for i in (0..8).rev() {
                bits.push(Boolean::constant((byte >> i) & 1 == 1));
            }
        }
        bits
    }

    fn test_input_output(input: &str, output: &str) {
        let sha = Sha2_256::<Circuit>::new();
        let input_bits = string_to_bits(input);
        let output_bits = sha.hash(&input_bits);
        assert_eq!(bits_to_hex_string(&output_bits), output);
    }

    #[test]
    fn test() {
        test_input_output("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        test_input_output("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        test_input_output(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
    }
}