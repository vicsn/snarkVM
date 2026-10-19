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

use crate::{
    FftField,
    Field,
    FieldError,
    FieldParameters,
    LegendreSymbol,
    One,
    PoseidonDefaultField,
    PoseidonDefaultParameters,
    PrimeField,
    SquareRootField,
    Zero,
};
use snarkvm_utilities::{
    FromBytes,
    ToBits,
    ToBytes,
    biginteger::{BigInteger as _BigInteger, BigInteger256 as BigInteger, arithmetic as fa},
    serialize::CanonicalDeserialize,
};

use std::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    io::{Read, Result as IoResult, Write},
    marker::PhantomData,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
};
use zeroize::Zeroize;

pub trait Fp256Parameters: FieldParameters<BigInteger = BigInteger> {}

#[derive(Copy, Clone, Default, PartialEq, Eq, Hash, Zeroize)]
pub struct Fp256<P: Fp256Parameters>(pub BigInteger, #[doc(hidden)] pub PhantomData<P>);

impl<P: Fp256Parameters> Fp256<P> {
    const MODULUS_62: [i64; 5] = to_signed62(&P::MODULUS.0);
    const MODULUS_INV_62: u64 = P::INV.wrapping_neg() & M62;
    const R2_62: [i64; 5] = to_signed62(&P::R2.0);

    #[inline]
    fn is_valid(&self) -> bool {
        self.0 < P::MODULUS
    }

    #[inline]
    fn reduce(&mut self) {
        if !self.is_valid() {
            self.0.sub_noborrow(&P::MODULUS);
        }
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn mont_reduce(
        &mut self,
        r0: u64,
        mut r1: u64,
        mut r2: u64,
        mut r3: u64,
        mut r4: u64,
        mut r5: u64,
        mut r6: u64,
        mut r7: u64,
    ) {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r0, k, P::MODULUS.0[0], &mut carry);
        r1 = fa::mac_with_carry(r1, k, P::MODULUS.0[1], &mut carry);
        r2 = fa::mac_with_carry(r2, k, P::MODULUS.0[2], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[3], &mut carry);
        carry = fa::adc(&mut r4, 0, carry);
        let carry2 = carry;
        let k = r1.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r1, k, P::MODULUS.0[0], &mut carry);
        r2 = fa::mac_with_carry(r2, k, P::MODULUS.0[1], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[2], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[3], &mut carry);
        carry = fa::adc(&mut r5, carry2, carry);
        let carry2 = carry;
        let k = r2.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r2, k, P::MODULUS.0[0], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[1], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[2], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[3], &mut carry);
        carry = fa::adc(&mut r6, carry2, carry);
        let carry2 = carry;
        let k = r3.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r3, k, P::MODULUS.0[0], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[1], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[2], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[3], &mut carry);
        fa::adc(&mut r7, carry2, carry);
        (self.0).0[0] = r4;
        (self.0).0[1] = r5;
        (self.0).0[2] = r6;
        (self.0).0[3] = r7;
        self.reduce();
    }

    /// Returns the inverse of a nonzero canonical element.
    ///
    /// Bernstein-Yang safegcd, as libsecp256k1's `modinv64_var`; its branches and running time depend on `self`.
    fn safegcd_inverse(&self) -> Self {
        debug_assert!(self.is_valid());
        let modulus = &Self::MODULUS_62;
        let mut d = [0i64; 5];
        let mut e = Self::R2_62;
        let mut f = *modulus;
        let mut g = to_signed62(&self.0.0);
        let mut len = 5;
        let mut eta = -1;
        loop {
            let t;
            (eta, t) = divsteps_62_var(eta, f[0] as u64, g[0] as u64);
            update_de_62(&mut d, &mut e, t, modulus, Self::MODULUS_INV_62);
            update_fg_62_var(len, &mut f, &mut g, t);
            if g[..len].iter().all(|&limb| limb == 0) {
                break;
            }
            let (f_top, g_top) = (f[len - 1], g[len - 1]);
            if len > 1 && f_top ^ (f_top >> 63) == 0 && g_top ^ (g_top >> 63) == 0 {
                f[len - 2] |= f_top << 62;
                g[len - 2] |= g_top << 62;
                len -= 1;
            }
        }
        Self(BigInteger(from_signed62(&normalize_62(d, f[len - 1], modulus))), PhantomData)
    }
}

impl<P: Fp256Parameters> Zero for Fp256<P> {
    #[inline]
    fn zero() -> Self {
        Self(BigInteger::from(0), PhantomData)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<P: Fp256Parameters> One for Fp256<P> {
    #[inline]
    fn one() -> Self {
        Self(P::R, PhantomData)
    }

    #[inline]
    fn is_one(&self) -> bool {
        self.0 == P::R
    }
}

impl<P: Fp256Parameters> Field for Fp256<P> {
    type BasePrimeField = Self;

    // 256/64 = 4 limbs.
    impl_field_from_random_bytes_with_flags!(4);

    fn from_base_prime_field(other: Self::BasePrimeField) -> Self {
        other
    }

    /// Returns the constant 2^{-1}.
    fn half() -> Self {
        // Compute 1/2 `(p+1)/2` as `1/2`.
        // This is cheaper than `Self::one().double().inverse()`
        let mut two_inv = P::MODULUS;
        two_inv.add_nocarry(&1u64.into());
        two_inv.div2();
        Self::from_bigint(two_inv).unwrap() // Guaranteed to be valid.
    }

    fn sum_of_products<'a>(a: &'a [Self], b: &'a [Self]) -> Self {
        // For a single `a x b` multiplication, operand scanning (schoolbook) takes each
        // limb of `a` in turn, and multiplies it by all of the limbs of `b` to compute
        // the result as a double-width intermediate representation, which is then fully
        // reduced at the end. Here however we have pairs of multiplications (a_i, b_i),
        // the results of which are summed.
        //
        // The intuition for this algorithm is two-fold:
        // - We can interleave the operand scanning for each pair, by processing the jth
        //   limb of each `a_i` together. As these have the same offset within the overall
        //   operand scanning flow, their results can be summed directly.
        // - We can interleave the multiplication and reduction steps, resulting in a
        //   single bitshift by the limb size after each iteration. This means we only
        //   need to store a single extra limb overall, instead of keeping around all the
        //   intermediate results and eventually having twice as many limbs.

        // Algorithm 2, line 2
        let (u0, u1, u2, u3) = (0..4).fold((0, 0, 0, 0), |(u0, u1, u2, u3), j| {
            // Algorithm 2, line 3
            // For each pair in the overall sum of products:
            let (t0, t1, t2, t3, mut t4) =
                a.iter().zip(b).fold((u0, u1, u2, u3, 0), |(t0, t1, t2, t3, mut t4), (a, b)| {
                    // Compute digit_j x row and accumulate into `u`.
                    let mut carry = 0;
                    let t0 = fa::mac_with_carry(t0, a.0.0[j], b.0.0[0], &mut carry);
                    let t1 = fa::mac_with_carry(t1, a.0.0[j], b.0.0[1], &mut carry);
                    let t2 = fa::mac_with_carry(t2, a.0.0[j], b.0.0[2], &mut carry);
                    let t3 = fa::mac_with_carry(t3, a.0.0[j], b.0.0[3], &mut carry);
                    let _ = fa::adc(&mut t4, 0, carry);

                    (t0, t1, t2, t3, t4)
                });

            // Algorithm 2, lines 4-5
            // This is a single step of the usual Montgomery reduction process.
            let k = t0.wrapping_mul(P::INV);
            let mut carry = 0;
            let _ = fa::mac_with_carry(t0, k, P::MODULUS.0[0], &mut carry);
            let r1 = fa::mac_with_carry(t1, k, P::MODULUS.0[1], &mut carry);
            let r2 = fa::mac_with_carry(t2, k, P::MODULUS.0[2], &mut carry);
            let r3 = fa::mac_with_carry(t3, k, P::MODULUS.0[3], &mut carry);
            let _ = fa::adc(&mut t4, 0, carry);
            let r4 = t4;

            (r1, r2, r3, r4)
        });

        // Because we represent F_p elements in non-redundant form, we need a final
        // conditional subtraction to ensure the output is in range.
        let mut result = Self(BigInteger([u0, u1, u2, u3]), PhantomData);
        result.reduce();
        result
    }

    #[inline]
    fn double(&self) -> Self {
        let mut temp = *self;
        temp.double_in_place();
        temp
    }

    #[inline]
    fn double_in_place(&mut self) {
        // This cannot exceed the backing capacity.
        self.0.mul2();
        // However, it may need to be reduced.
        self.reduce();
    }

    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        P::MODULUS.as_ref()
    }

    #[inline]
    fn square(&self) -> Self {
        let mut temp = *self;
        temp.square_in_place();
        temp
    }

    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        // i = 0
        let mut carry = 0;
        let r1 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[1], &mut carry);
        let r2 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[2], &mut carry);
        let r3 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[3], &mut carry);
        let r4 = carry;
        let mut carry = 0;
        let r3 = fa::mac_with_carry(r3, (self.0).0[1], (self.0).0[2], &mut carry);
        let r4 = fa::mac_with_carry(r4, (self.0).0[1], (self.0).0[3], &mut carry);
        let r5 = carry;
        let mut carry = 0;
        let r5 = fa::mac_with_carry(r5, (self.0).0[2], (self.0).0[3], &mut carry);
        let r6 = carry;

        let mut r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let mut r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let mut r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let mut r1 = r1 << 1;

        let mut carry = 0;
        let r0 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[0], &mut carry);
        carry = fa::adc(&mut r1, 0, carry);
        let r2 = fa::mac_with_carry(r2, (self.0).0[1], (self.0).0[1], &mut carry);
        carry = fa::adc(&mut r3, 0, carry);
        let r4 = fa::mac_with_carry(r4, (self.0).0[2], (self.0).0[2], &mut carry);
        carry = fa::adc(&mut r5, 0, carry);
        let r6 = fa::mac_with_carry(r6, (self.0).0[3], (self.0).0[3], &mut carry);
        fa::adc(&mut r7, 0, carry);

        self.mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
        self
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        if self.is_zero() { None } else { Some(self.safegcd_inverse()) }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if let Some(inverse) = self.inverse() {
            *self = inverse;
            Some(self)
        } else {
            None
        }
    }

    #[inline]
    fn frobenius_map(&mut self, _: usize) {
        // No-op: No effect in a prime field.
    }
}

impl<P: Fp256Parameters> PrimeField for Fp256<P> {
    type BigInteger = BigInteger;
    type Parameters = P;

    #[inline]
    fn from_bigint(r: BigInteger) -> Option<Self> {
        let mut r = Fp256(r, PhantomData);
        if r.is_zero() {
            Some(r)
        } else if r.is_valid() {
            r *= &Fp256(P::R2, PhantomData);
            Some(r)
        } else {
            None
        }
    }

    #[inline]
    fn to_bigint(&self) -> BigInteger {
        let mut tmp = self.0;
        let mut r = tmp.0;
        // Montgomery Reduction
        let k = r[0].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[0], k, P::MODULUS.0[0], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry);
        r[0] = carry;

        let k = r[1].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[1], k, P::MODULUS.0[0], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[1], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[2], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[3], &mut carry);
        r[1] = carry;

        let k = r[2].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[2], k, P::MODULUS.0[0], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[1], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[2], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[3], &mut carry);
        r[2] = carry;

        let k = r[3].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[3], k, P::MODULUS.0[0], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[1], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[2], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[3], &mut carry);
        r[3] = carry;

        tmp.0 = r;
        tmp
    }

    #[inline]
    fn decompose(
        &self,
        q1: &[u64; 4],
        q2: &[u64; 4],
        b1: Self,
        b2: Self,
        r128: Self,
        half_r: &[u64; 8],
    ) -> (Self, Self, bool, bool) {
        let mul_short = |a: &[u64; 4], b: &[u64; 4]| -> [u64; 8] {
            // Schoolbook multiplication
            let mut carry = 0;
            let r0 = fa::mac_with_carry(0, a[0], b[0], &mut carry);
            let r1 = fa::mac_with_carry(0, a[0], b[1], &mut carry);
            let r2 = fa::mac_with_carry(0, a[0], b[2], &mut carry);
            let r3 = carry;

            let mut carry = 0;
            let r1 = fa::mac_with_carry(r1, a[1], b[0], &mut carry);
            let r2 = fa::mac_with_carry(r2, a[1], b[1], &mut carry);
            let r3 = fa::mac_with_carry(r3, a[1], b[2], &mut carry);
            let r4 = carry;

            let mut carry = 0;
            let r2 = fa::mac_with_carry(r2, a[2], b[0], &mut carry);
            let r3 = fa::mac_with_carry(r3, a[2], b[1], &mut carry);
            let r4 = fa::mac_with_carry(r4, a[2], b[2], &mut carry);
            let r5 = carry;

            let mut carry = 0;
            let r3 = fa::mac_with_carry(r3, a[3], b[0], &mut carry);
            let r4 = fa::mac_with_carry(r4, a[3], b[1], &mut carry);
            let r5 = fa::mac_with_carry(r5, a[3], b[2], &mut carry);
            let r6 = carry;

            [r0, r1, r2, r3, r4, r5, r6, 0]
        };

        let round = |a: &mut [u64; 8]| -> Self {
            let mut carry = 0;
            // NOTE: can the first 4 be omitted?
            carry = fa::adc(&mut a[0], half_r[0], carry);
            carry = fa::adc(&mut a[1], half_r[1], carry);
            carry = fa::adc(&mut a[2], half_r[2], carry);
            carry = fa::adc(&mut a[3], half_r[3], carry);
            carry = fa::adc(&mut a[4], half_r[4], carry);
            carry = fa::adc(&mut a[5], half_r[5], carry);
            carry = fa::adc(&mut a[6], half_r[6], carry);
            _ = fa::adc(&mut a[7], half_r[7], carry);
            Self::from_bigint(BigInteger([a[4], a[5], a[6], a[7]])).unwrap()
        };

        let alpha = |x: &Self, q: &[u64; 4]| -> Self {
            let mut a = mul_short(&x.to_bigint().0, q);
            round(&mut a)
        };

        let alpha1 = alpha(self, q1);
        let alpha2 = alpha(self, q2);
        let z1 = alpha1 * b1;
        let z2 = alpha2 * b2;

        let mut k1 = *self - z1 - alpha2;
        let mut k2 = z2 - alpha1;
        let mut k1_neg = false;
        let mut k2_neg = false;

        if k1 > r128 {
            k1 = -k1;
            k1_neg = true;
        }

        if k2 > r128 {
            k2 = -k2;
            k2_neg = true;
        }

        (k1, k2, k1_neg, k2_neg)
    }
}

impl<P: Fp256Parameters> FftField for Fp256<P> {
    type FftParameters = P;

    #[inline]
    fn two_adic_root_of_unity() -> Self {
        Self(P::TWO_ADIC_ROOT_OF_UNITY, PhantomData)
    }

    #[inline]
    fn large_subgroup_root_of_unity() -> Option<Self> {
        Some(Self(P::LARGE_SUBGROUP_ROOT_OF_UNITY?, PhantomData))
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(P::GENERATOR, PhantomData)
    }
}

impl<P: Fp256Parameters> SquareRootField for Fp256<P> {
    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        use crate::LegendreSymbol::*;

        // s = self^((MODULUS - 1) // 2)
        let mut s = self.pow(P::MODULUS_MINUS_ONE_DIV_TWO);
        s.reduce();

        if s.is_zero() {
            Zero
        } else if s.is_one() {
            QuadraticResidue
        } else {
            QuadraticNonResidue
        }
    }

    #[inline]
    fn sqrt(&self) -> Option<Self> {
        sqrt_impl!(Self, P, self)
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        (*self).sqrt().map(|sqrt| {
            *self = sqrt;
            self
        })
    }
}

/// `Fp` elements are ordered lexicographically.
impl<P: Fp256Parameters> Ord for Fp256<P> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bigint().cmp(&other.to_bigint())
    }
}

impl<P: Fp256Parameters> PartialOrd for Fp256<P> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Fp256Parameters + PoseidonDefaultParameters> PoseidonDefaultField for Fp256<P> {}

impl_primefield_from_int!(Fp256, u128, Fp256Parameters);
impl_primefield_from_int!(Fp256, u64, Fp256Parameters);
impl_primefield_from_int!(Fp256, u32, Fp256Parameters);
impl_primefield_from_int!(Fp256, u16, Fp256Parameters);
impl_primefield_from_int!(Fp256, u8, Fp256Parameters);

impl_primefield_standard_sample!(Fp256, Fp256Parameters);

impl_add_sub_from_field_ref!(Fp256, Fp256Parameters);
impl_mul_div_from_field_ref!(Fp256, Fp256Parameters);

impl<P: Fp256Parameters> ToBits for Fp256<P> {
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        let initial_len = vec.len();
        self.to_bigint().write_bits_le(vec);
        vec.truncate(initial_len + P::MODULUS_BITS as usize);
    }

    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }

    fn num_bits() -> Option<usize> {
        Some(256)
    }
}

impl<P: Fp256Parameters> ToBytes for Fp256<P> {
    #[inline]
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.to_bigint().write_le(writer)
    }
}

impl<P: Fp256Parameters> FromBytes for Fp256<P> {
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        BigInteger::read_le(reader).and_then(|b| match Self::from_bigint(b) {
            Some(f) => Ok(f),
            None => Err(FieldError::InvalidFieldElement.into()),
        })
    }
}

impl<P: Fp256Parameters> FromStr for Fp256<P> {
    type Err = FieldError;

    /// Interpret a string of numbers as a (congruent) prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(FieldError::ParsingEmptyString);
        }

        if s == "0" {
            return Ok(Self::zero());
        }

        let mut res = Self::zero();

        let ten =
            Self::from_bigint(<Self as PrimeField>::BigInteger::from(10)).ok_or(FieldError::InvalidFieldElement)?;

        let mut first_digit = true;

        for c in s.chars() {
            match c.to_digit(10) {
                Some(c) => {
                    if first_digit {
                        if c == 0 {
                            return Err(FieldError::InvalidString);
                        }

                        first_digit = false;
                    }

                    res.mul_assign(&ten);
                    res.add_assign(
                        &Self::from_bigint(<Self as PrimeField>::BigInteger::from(u64::from(c)))
                            .ok_or(FieldError::InvalidFieldElement)?,
                    );
                }
                None => return Err(FieldError::ParsingNonDigitCharacter),
            }
        }

        if !res.is_valid() { Err(FieldError::InvalidFieldElement) } else { Ok(res) }
    }
}

impl<P: Fp256Parameters> Debug for Fp256<P> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_bigint())
    }
}

impl<P: Fp256Parameters> Display for Fp256<P> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_bigint())
    }
}

impl<P: Fp256Parameters> Neg for Fp256<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if !self.is_zero() {
            let mut tmp = P::MODULUS;
            tmp.sub_noborrow(&self.0);
            Self(tmp, PhantomData)
        } else {
            self
        }
    }
}

impl<P: Fp256Parameters> Add<&'_ Fp256<P>> for Fp256<P> {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        let mut result = self;
        result.add_assign(other);
        result
    }
}

impl<P: Fp256Parameters> Sub<&'_ Fp256<P>> for Fp256<P> {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        let mut result = self;
        result.sub_assign(other);
        result
    }
}

impl<P: Fp256Parameters> Mul<&'_ Fp256<P>> for Fp256<P> {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(other);
        result
    }
}

impl<P: Fp256Parameters> Div<&'_ Fp256<P>> for Fp256<P> {
    type Output = Self;

    #[inline]
    fn div(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other.inverse().unwrap());
        result
    }
}

impl<P: Fp256Parameters> AddAssign<&'_ Self> for Fp256<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        // This cannot exceed the backing capacity.
        self.0.add_nocarry(&other.0);
        // However, it may need to be reduced.
        self.reduce();
    }
}

impl<P: Fp256Parameters> SubAssign<&'_ Self> for Fp256<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        // If `other` is larger than `self`, add the modulus to self first.
        if other.0 > self.0 {
            self.0.add_nocarry(&P::MODULUS);
        }

        self.0.sub_noborrow(&other.0);
    }
}

impl<P: Fp256Parameters> MulAssign<&'_ Self> for Fp256<P> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        let mut r = [0u64; 4];
        let mut carry1 = 0u64;
        let mut carry2 = 0u64;

        // Iteration 0.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[0], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[0], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[0], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[0], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);
        r[3] = carry1 + carry2;

        // Iteration 1.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[1], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[1], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[1], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[1], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);
        r[3] = carry1 + carry2;

        // Iteration 2.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[2], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[2], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[2], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[2], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);
        r[3] = carry1 + carry2;

        // Iteration 3.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[3], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[3], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[3], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[3], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);
        r[3] = carry1 + carry2;

        (self.0).0 = r;
        self.reduce();
    }
}

impl<P: Fp256Parameters> DivAssign<&'_ Self> for Fp256<P> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}

// The loop in `Fp256::safegcd_inverse` and the functions `divsteps_62_var`, `update_de_62`,
// `update_fg_62_var` and `normalize_62` are ported from `src/modinv64_impl.h` in libsecp256k1
// (https://github.com/bitcoin-core/secp256k1), which is distributed under the following notice:
//
// Copyright (c) 2020 Peter Dettman
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

const M62: u64 = u64::MAX >> 2;

#[inline]
const fn to_signed62(a: &[u64; 4]) -> [i64; 5] {
    [
        (a[0] & M62) as i64,
        ((a[0] >> 62 | a[1] << 2) & M62) as i64,
        ((a[1] >> 60 | a[2] << 4) & M62) as i64,
        ((a[2] >> 58 | a[3] << 6) & M62) as i64,
        (a[3] >> 56) as i64,
    ]
}

#[inline]
fn from_signed62(v: &[i64; 5]) -> [u64; 4] {
    let v = v.map(|limb| limb as u64);
    [v[0] | v[1] << 62, v[1] >> 2 | v[2] << 60, v[2] >> 4 | v[3] << 58, v[3] >> 6 | v[4] << 56]
}

#[inline]
/// Runs 62 divsteps on the low limbs of `f` and `g`, returning `eta` and the transition matrix `[u, v, q, r]`.
fn divsteps_62_var(mut eta: i64, mut f: u64, mut g: u64) -> (i64, [i64; 4]) {
    let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
    let mut i = 62u32;
    loop {
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros as i64;
        i -= zeros;
        if i == 0 {
            break;
        }
        let w = if eta < 0 {
            eta = -eta;
            (f, g) = (g, f.wrapping_neg());
            (u, q) = (q, u.wrapping_neg());
            (v, r) = (r, v.wrapping_neg());
            let limit = (eta + 1).min(i as i64) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 63;
            f.wrapping_mul(g).wrapping_mul(f.wrapping_mul(f).wrapping_sub(2)) & mask
        } else {
            let limit = (eta + 1).min(i as i64) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 15;
            f.wrapping_add((f.wrapping_add(1) & 4) << 1).wrapping_neg().wrapping_mul(g) & mask
        };
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }
    (eta, [u as i64, v as i64, q as i64, r as i64])
}

#[inline]
/// Sets `[d, e]` to `t [d, e] / 2^62 mod p`, keeping both in `(-2p, p)`.
fn update_de_62(d: &mut [i64; 5], e: &mut [i64; 5], t: [i64; 4], modulus: &[i64; 5], modulus_inv_62: u64) {
    let [u, v, q, r] = t;
    let (sd, se) = (d[4] >> 63, e[4] >> 63);
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    let [u, v, q, r] = t.map(i128::from);
    let mut cd = u * d[0] as i128 + v * e[0] as i128;
    let mut ce = q * d[0] as i128 + r * e[0] as i128;
    md -= (modulus_inv_62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64;
    me -= (modulus_inv_62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64;
    cd += modulus[0] as i128 * md as i128;
    ce += modulus[0] as i128 * me as i128;
    cd >>= 62;
    ce >>= 62;
    for i in 1..5 {
        cd += u * d[i] as i128 + v * e[i] as i128 + modulus[i] as i128 * md as i128;
        ce += q * d[i] as i128 + r * e[i] as i128 + modulus[i] as i128 * me as i128;
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d[4] = cd as i64;
    e[4] = ce as i64;
    debug_assert!([d, e].iter().all(|x| sign_62(x, modulus, 2) > 0 && sign_62(x, modulus, -1) < 0));
}

#[inline]
/// Sets `[f, g]` to `t [f, g] / 2^62` over their low `len` limbs.
fn update_fg_62_var(len: usize, f: &mut [i64; 5], g: &mut [i64; 5], t: [i64; 4]) {
    let [u, v, q, r] = t.map(i128::from);
    let mut cf = (u * f[0] as i128 + v * g[0] as i128) >> 62;
    let mut cg = (q * f[0] as i128 + r * g[0] as i128) >> 62;
    for i in 1..len {
        cf += u * f[i] as i128 + v * g[i] as i128;
        cg += q * f[i] as i128 + r * g[i] as i128;
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[len - 1] = cf as i64;
    g[len - 1] = cg as i64;
}

#[inline]
/// Maps `r` in `(-2p, p)` to `sign(sign) * r mod p` in `[0, p)`.
fn normalize_62(mut r: [i64; 5], sign: i64, modulus: &[i64; 5]) -> [i64; 5] {
    let add = r[4] >> 63;
    let negate = sign >> 63;
    for (limb, m) in r.iter_mut().zip(modulus) {
        *limb = ((*limb + (m & add)) ^ negate) - negate;
    }
    carry_62(&mut r);
    let add = r[4] >> 63;
    for (limb, m) in r.iter_mut().zip(modulus) {
        *limb += m & add;
    }
    carry_62(&mut r);
    r
}

#[inline]
fn carry_62(r: &mut [i64; 5]) {
    for i in 0..4 {
        r[i + 1] += r[i] >> 62;
        r[i] &= M62 as i64;
    }
}

/// Returns the sign of `a + k * modulus`.
fn sign_62(a: &[i64; 5], modulus: &[i64; 5], k: i64) -> i64 {
    let (mut carry, mut nonzero) = (0i128, false);
    for (limb, m) in a.iter().zip(modulus) {
        carry += *limb as i128 + k as i128 * *m as i128;
        nonzero |= carry as u64 & M62 != 0;
        carry >>= 62;
    }
    if carry != 0 { carry.signum() as i64 } else { nonzero as i64 }
}
