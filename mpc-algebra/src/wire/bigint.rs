use serde::{Deserialize, Serialize, Deserializer, Serializer};
use snarkvm_curves::bls12_377::{G1Affine, G2Affine};
use snarkvm_curves::PairingCurve;
use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
// use ark_ff::bytes::{FromBytes, ToBytes};
// use ark_ff::prelude::*;
use snarkvm_fields::{Field, FftField, PrimeField, Zero, One, SquareRootField, FftParameters, ToConstraintField, ConstraintFieldError};
use snarkvm_fields::FieldParameters;
use snarkvm_utilities::{
    BigInteger, CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, Compress, Flags, FromBits, FromBytes, SerializationError, ToBits, ToBytes, Uniform, Valid, Validate,
};
use num_bigint::BigUint;
use std::io::{self, Read, Write};
use aleo_std::{end_timer, start_timer};
use core::ops::*;
use derivative::Derivative;
use rand::{Rng, distributions::{Distribution, Standard}};
use std::cmp::Ord;
use std::default::Default;
use std::fmt::{self, Debug, Formatter}; // Display
use std::hash::Hash;
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use zeroize::Zeroize;

use snarkvm_curves::MpcWire;
use crate::{MpcProjectiveGroup, MpcAffineGroup};
use crate::MpcField;
use crate::FieldShare;
use crate::PairingShare;

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct MpcBigInteger<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger>{
    pub val: T, // TODO: maybe this can be <F as PrimeField>::BigInteger, and then we only have to parametrize on F and S
    pub _marker: PhantomData<(F, S)>,
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> BigInteger for MpcBigInteger<F, S, T> {
    const NUM_LIMBS: usize = T::NUM_LIMBS;

    /// Add another representation to this one, returning the carry bit.
    fn add_nocarry(&mut self, other: &Self) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Subtract another representation from this one, returning the borrow bit.
    fn sub_noborrow(&mut self, other: &Self) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Performs a leftwise bitshift of this number, effectively multiplying
    /// it by 2. Overflow is ignored.
    fn mul2(&mut self) {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Performs a leftwise bitshift of this number by some amount.
    fn muln(&mut self, amt: u32) {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Performs a rightwise bitshift of this number, effectively dividing
    /// it by 2.
    fn div2(&mut self) {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Performs a rightwise bitshift of this number by some amount.
    fn divn(&mut self, amt: u32) {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Returns true iff this number is odd.
    fn is_odd(&self) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Returns true if this number is even.
    fn is_even(&self) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Returns true if this number is zero.
    fn is_zero(&self) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Compute the number of bits needed to encode this number. Always a
    /// multiple of 64.
    fn num_bits(&self) -> u32 {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Compute the `i`-th bit of `self`.
    fn get_bit(&self, i: usize) -> bool {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Returns the BigUint representation.
    fn to_biguint(&self) -> BigUint {
        unimplemented!("MpcBigInteger::BigInteger");
    }

    /// Returns a vector for wnaf.
    fn find_wnaf(&self) -> Vec<i64> {
        unimplemented!("MpcBigInteger::BigInteger");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> From<u64> for MpcBigInteger<F, S, T> {
    #[inline]
    fn from(val: u64) -> Self {
        unimplemented!("MpcBigInteger::BigInteger::From");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> std::fmt::Display for MpcBigInteger<F, S, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!("MpcBigInteger::BigInteger::Display");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> Default for MpcBigInteger<F, S, T> {
    fn default() -> Self {
        unimplemented!("MpcBigInteger::BigInteger::Default");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> AsRef<[u64]> for MpcBigInteger<F, S, T> {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        unimplemented!("MpcBigInteger::BigInteger::AsRef");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> AsMut<[u64]> for MpcBigInteger<F, S, T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        unimplemented!("MpcBigInteger::BigInteger::AsMut");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> FromBytes for MpcBigInteger<F, S, T> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        unimplemented!("MpcBigInteger::BigInteger::FromBytes");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> ToBytes for MpcBigInteger<F, S, T> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        unimplemented!("MpcBigInteger::BigInteger::ToBytes");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> FromBits for MpcBigInteger<F, S, T> {
    /// Initializes a new compute key from a list of **little-endian** bits.
    fn from_bits_le(bits: &[bool]) -> anyhow::Result<Self> {
        unimplemented!("MpcBigInteger::BigInteger::FromBits::from_bits_le");
    }
    /// Initializes a new compute key from a list of **big-endian** bits.
    fn from_bits_be(bits: &[bool]) -> anyhow::Result<Self> {
        unimplemented!("MpcBigInteger::BigInteger::FromBits::from_bits_be");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> ToBits for MpcBigInteger<F, S, T> {
    /// Writes `self` into the given vector as a boolean array in little-endian order.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        unimplemented!("MpcBigInteger::BigInteger::FromBits::to_bits_le");
    }

    /// Writes `self` into the given vector as a boolean array in big-endian order.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        unimplemented!("MpcBigInteger::BigInteger::FromBits::to_bits_le");
    }

    // /// Returns this ciphertext as a list of **little-endian** bits.
    // fn to_bits_le(&self) -> Vec<bool> {
    //     unimplemented!("MpcBigInteger::BigInteger::FromBits::to_bits_le");
    // }

    // /// Returns this ciphertext as a list of **big-endian** bits.
    // fn to_bits_be(&self) -> Vec<bool> {
    //     unimplemented!("MpcBigInteger::BigInteger::FromBits::to_bits_be");
    // }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> Distribution<MpcBigInteger<F, S, T>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MpcBigInteger<F, S, T> {
        unimplemented!("MpcBigInteger::BigInteger::Distribution::sample");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger> From<MpcField<F, S>> for MpcBigInteger<F, S, T> {
    fn from(value: MpcField<F, S>) -> Self {
        match value {
            MpcField::Public(f) => Self{
                val: f.to_bigint(),
                _marker: PhantomData,
            },
            MpcField::Shared(f) => {
                unimplemented!("Shared field into BigInteger")
            },
        }
    }
}

// impl<E: PairingEngine, PS: PairingShare<E>, T: BigInteger> Deref for BigIntegerWrapper<E, PS, T> {
//     type Target = T;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
// impl<E: PairingEngine, PS: PairingShare<E>> From<MpcField<E::Fr, PS::FrShare>> 
//     for BigIntegerWrapper<E, PS, <<E as PairingEngine>::Fr as PrimeField>::BigInteger> 
// {
//     fn from(value: MpcField<E::Fr, PS::FrShare>) -> Self {
//         match value {
//             MpcField::Public(f) => BigIntegerWrapper{
//                 val: f.to_bigint(),
//                 _marker: PhantomData,
//             },
//             MpcField::Shared(_) => {
//                 unimplemented!("Shared field into BigInteger")
//             }
//         }
//     }
// }

// NOTE: conflicting implementations issue.
// impl<E: PairingEngine, PS: PairingShare<E>> From<MpcField<E::Fr, PS::FrShare>> for <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger {
//     fn from(value: MpcField<E::Fr, PS::FrShare>) -> Self {
//         match value {
//             MpcField::Public(f) => BigIntegerWrapper{
//                 val: f.to_bigint(),
//                 _marker: PhantomData,
//             },
//             MpcField::Shared(f) => {
//                 unimplemented!("Shared field into BigInteger")
//             },
//         }
//     }
// }

// impl<E: PairingEngine, PS: PairingShare<E>, T: BigInteger> Into<T> for MpcField<E::Fr, PS::FrShare> {
//     fn into(self) -> T {
//         match self {
//             MpcField::Public(f) => f.to_bigint(),
//             MpcField::Shared(f) => {
//                 unimplemented!("Shared field into BigInteger")
//             },
//         }
//     }
// }