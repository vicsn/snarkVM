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

use std::ops::{BitAnd, BitOr, BitXor, Not};
use snarkvm_circuit_types::environment::{AddWrapped, FromBits, Inject, ToBits};
use snarkvm_circuit_types::U32;
use super::*;

impl<E: Environment> Hash for Ripemd160<E> {
    type Input = Boolean<E>;
    type Output = Vec<Boolean<E>>;

    fn hash(&self, input: &[Self::Input]) -> Self::Output {

        // Pad the message according to MD4 (RFC 1320).
        let bits = pad(input);

        // Divide the padded message into 512-bit chunks.
        let chunks = bits.chunks(512);

        // Initial hash values.
        let mut h0: U32<E> = U32::constant(console::U32::new(0x67452301));
        let mut h1: U32<E> = U32::constant(console::U32::new(0xEFCDAB89));
        let mut h2: U32<E> = U32::constant(console::U32::new(0x98BADCFE));
        let mut h3: U32<E> = U32::constant(console::U32::new(0x10325476));
        let mut h4: U32<E> = U32::constant(console::U32::new(0xC3D2E1F0));

        // Outer loop.
        for chunk in chunks {
            // A, B, C, D, E.
            let mut a: U32<E> = h0.clone();
            let mut b: U32<E> = h1.clone();
            let mut c: U32<E> = h2.clone();
            let mut d: U32<E> = h3.clone();
            let mut e: U32<E> = h4.clone();

            // A', B', C', D', E'.
            let mut ap: U32<E> = h0.clone();
            let mut bp: U32<E> = h1.clone();
            let mut cp: U32<E> = h2.clone();
            let mut dp: U32<E> = h3.clone();
            let mut ep: U32<E> = h4.clone();

            // Convert the chunk of 512 bits to a sequence of 16 32-bit words.
            let mut xi = Vec::with_capacity(16);
            for word in chunk.chunks(32) {
                let mut xi_bits = Vec::with_capacity(32);
                for i in 0..4 {
                    for j in (0..8).rev() {
                        xi_bits.push(word[i * 8 + j].clone());
                    }
                }
                xi.push(U32::from_bits_le(xi_bits.as_slice()));
            }

            // Inner loop.
            for j in 0..80 {
                let rj = R[j] as usize;
                let rpj = RP[j] as usize;
                let xi_rj = &xi[rj];
                let xi_rpj = &xi[rpj];
                let kj = U32::constant(console::U32::new(K[j/16]));
                let kpj = U32::constant(console::U32::new(KP[j/16]));
                let mut t = rol(S[j], &a.add_wrapped(&f(j, &b, &c, &d)).add_wrapped(&xi_rj).add_wrapped(&kj))
                    .add_wrapped(&e);
                a = e;
                e = d.clone();
                d = rol(10, &c);
                c = b.clone();
                b = t;
                t = rol(SP[j], &ap.add_wrapped(&f(79 - j, &bp, &cp, &dp)).add_wrapped(&xi_rpj).add_wrapped(&kpj))
                    .add_wrapped(&ep);
                ap = ep.clone();
                ep = dp.clone();
                dp = rol(10, &cp);
                cp = bp.clone();
                bp = t.clone();
            }

            // Update the hash values.
            let t = h1.add_wrapped(&c).add_wrapped(&dp);
            h1 = h2.add_wrapped(&d).add_wrapped(&ep);
            h2 = h3.add_wrapped(&e).add_wrapped(&ap);
            h3 = h4.add_wrapped(&a).add_wrapped(&bp);
            h4 = h0.add_wrapped(&b).add_wrapped(&cp);
            h0 = t;
        }

        // Output final hash value, from h0 to h4 in that order, each word in big endian order.
        let mut output = Vec::with_capacity(160);
        for word in [h0, h1, h2, h3, h4].iter() {
            let byte0 = &word.to_bits_le()[0..8];
            let byte1 = &word.to_bits_le()[8..16];
            let byte2 = &word.to_bits_le()[16..24];
            let byte3 = &word.to_bits_le()[24..32];
            for bit in byte0.iter().rev() {
                output.push(bit.clone());
            }
            for bit in byte1.iter().rev() {
                output.push(bit.clone());
            }
            for bit in byte2.iter().rev() {
                output.push(bit.clone());
            }
            for bit in byte3.iter().rev() {
                output.push(bit.clone());
            }
        }
        output
    }
}

/// The function f.
fn f<E: Environment>(j: usize, x: &U32<E>, y: &U32<E>, z: &U32<E>) -> U32<E> {
    match j {
        0..=15 => x.bitxor(y).bitxor(z),
        16..=31 => x.clone().bitand(y).bitor(x.not().bitand(z)),
        32..=47 => x.bitor(y.not()).bitxor(z),
        48..=63 => x.bitand(z).bitor(y.bitand(z.not())),
        64..=79 => x.bitxor(y.bitor(z.not())),
        _ => unreachable!(),
    }
}

/// The function rol.
fn rol<E: Environment>(s: u8, x: &U32<E>) -> U32<E> {
    let mut bits = x.to_bits_be();
    bits.rotate_left(s as usize);
    U32::from_bits_be(&bits)
}

/// Pad the message according to MD4.
fn pad<E: Environment>(input: &[Boolean<E>]) -> Vec<Boolean<E>> {
    let mut padded = input.to_vec();

    // Add a '1' bit.
    padded.push(Boolean::constant(true));

    // Add as many '0' bits as needed to make the length congruent to 448 mod 512,
    // so that there are exactly 64 bits left for the length (448 + 64 = 512).
    while (padded.len() + 64) % 512 != 0 {
        padded.push(Boolean::constant(false));
    }

    // In the unlikely case that the length is >= 2^64,
    // we keep the lowest 64 bits anyway, as specified in the MD4 padding (RFC 1320).
    let len = input.len() as u64;

    // We allocate new circuit constants for the 64 bits of the length
    // because the circuit is for the specific length, although the message bits may vary.
    // But the bits are in a slightly complicated order (see RFC 1320):
    // first the low 32 bits, with the 4 bytes in little endian order, and each byte in big endian order;
    // then the high 32 bits, with the 4 bytes in little endian order, and each byte in big endian order.
    let low = (len & 0xFFFFFFFF) as u32;
    let high = (len >> 32) as u32;
    let low_bytes = low.to_le_bytes();
    let high_bytes = high.to_le_bytes();
    let bytes = [low_bytes, high_bytes].concat();
    for byte in bytes.iter() {
        for i in (0..8).rev() {
            padded.push(Boolean::constant((byte >> i) & 1u8 == 1u8));
        }
    }

    // The result has a length that is a multiple of 512.
    padded
}

/// The constant function s.
const S: [u8; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// The constant function s'.
const SP: [u8; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// The constant function r.
const R: [u8; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// The constant function r'.
const RP: [u8; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// The constant function K.
const K: [u32; 5] = [
    0x00000000,
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xA953FD4E,
];

/// The constant function K'.
const KP: [u32; 5] = [
    0x50A28BE6,
    0x5C4DD124,
    0x6D703EF3,
    0x7A6D76E9,
    0x00000000,
];

#[cfg(test)]
mod tests {
    use snarkvm_circuit_types::{
        Boolean,
        environment::{Circuit, Eject, Inject},
    };
    use crate::Hash;
    use crate::ripemd160::Ripemd160;

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
        let ripemd = Ripemd160::<Circuit>::new();
        let input_bits = string_to_bits(input);
        let output_bits = ripemd.hash(&input_bits);
        assert_eq!(bits_to_hex_string(&output_bits), output);
    }

    #[test]
    fn test() {
        test_input_output("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        test_input_output("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
        test_input_output("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    }
}