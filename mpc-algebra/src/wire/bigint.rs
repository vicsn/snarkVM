use snarkvm_fields::PrimeField;
use snarkvm_utilities::{BigInteger, FromBits, ToBits, FromBytes, ToBytes};
use num_bigint::BigUint;
use std::io::{self, Read, Write};
use rand::{Rng, distributions::{Distribution, Standard}};
use std::cmp::Ord;
use std::default::Default;
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use zeroize::Zeroize;

use crate::MpcField;
use crate::FieldShare;

/// In order to create MpcField, we need to impl From<MpcField> for BigInteger.
/// However, that is not an easy thing as BigInteger is not local. Not sure how this was possible with the PrimeField type.
/// We can overcome the barrier by creating a local transparant wrapper around BigInteger.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct MpcBigInteger<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static>{
    pub val: &'static T, // TODO: maybe this can be <F as PrimeField>::BigInteger, and then we only have to parametrize on F and S
    pub _marker: PhantomData<(F, S)>,
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> BigInteger for &'static MpcBigInteger<F, S, T> {
    const NUM_LIMBS: usize = T::NUM_LIMBS;

    /// Add another representation to this one, returning the carry bit.
    fn add_nocarry(&mut self, other: &Self) -> bool {
        self.val.add_nocarry(&other.val)
    }

    /// Subtract another representation from this one, returning the borrow bit.
    fn sub_noborrow(&mut self, other: &Self) -> bool {
        self.val.sub_noborrow(&other.val)
    }

    /// Performs a leftwise bitshift of this number, effectively multiplying
    /// it by 2. Overflow is ignored.
    fn mul2(&mut self) {
        self.val.mul2();
    }

    /// Performs a leftwise bitshift of this number by some amount.
    fn muln(&mut self, amt: u32) {
        self.val.muln(amt);
    }

    /// Performs a rightwise bitshift of this number, effectively dividing
    /// it by 2.
    fn div2(&mut self) {
        self.val.div2();
    }

    /// Performs a rightwise bitshift of this number by some amount.
    fn divn(&mut self, amt: u32) {
        self.val.divn(amt);
    }

    /// Returns true iff this number is odd.
    fn is_odd(&self) -> bool {
        self.val.is_odd()
    }

    /// Returns true if this number is even.
    fn is_even(&self) -> bool {
        self.val.is_even()
    }

    /// Returns true if this number is zero.
    fn is_zero(&self) -> bool {
        self.val.is_zero()
    }

    /// Compute the number of bits needed to encode this number. Always a
    /// multiple of 64.
    fn num_bits(&self) -> u32 {
        self.val.num_bits()
    }

    /// Compute the `i`-th bit of `self`.
    fn get_bit(&self, i: usize) -> bool {
        self.val.get_bit(i)
    }

    /// Returns the BigUint representation.
    fn to_biguint(&self) -> BigUint {
        self.val.to_biguint()
    }

    /// Returns a vector for wnaf.
    fn find_wnaf(&self) -> Vec<i64> {
        self.val.find_wnaf()
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> From<u64> for &'static MpcBigInteger<F, S, T> {
    #[inline]
    fn from(val: u64) -> Self {
        &'static MpcBigInteger::<F, S, T> {
            val: &'static T::from(val),
            _marker: PhantomData,
        }
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> std::fmt::Display for &'static MpcBigInteger<F, S, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!("MpcBigInteger::BigInteger::Display");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> Default for &'static MpcBigInteger<F, S, T> {
    fn default() -> Self {
        unimplemented!("MpcBigInteger::BigInteger::Default");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> AsRef<[u64]> for &'static MpcBigInteger<F, S, T> {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        unimplemented!("MpcBigInteger::BigInteger::AsRef");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> AsMut<[u64]> for &'static MpcBigInteger<F, S, T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        unimplemented!("MpcBigInteger::BigInteger::AsMut");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> FromBytes for &'static MpcBigInteger<F, S, T> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        unimplemented!("MpcBigInteger::BigInteger::FromBytes");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> ToBytes for &'static MpcBigInteger<F, S, T> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        unimplemented!("MpcBigInteger::BigInteger::ToBytes");
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> FromBits for &'static MpcBigInteger<F, S, T> {
    /// Initializes a new compute key from a list of **little-endian** bits.
    fn from_bits_le(_bits: &[bool]) -> anyhow::Result<Self> {
        unimplemented!("MpcBigInteger::BigInteger::FromBits::from_bits_le");
    }
    /// Initializes a new compute key from a list of **big-endian** bits.
    fn from_bits_be(bits: &[bool]) -> anyhow::Result<Self> {
        Ok(&'static MpcBigInteger::<F, S, T>{
            val: &'static FromBits::from_bits_be(bits)?,
            _marker: PhantomData,
        })
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> ToBits for &'static MpcBigInteger<F, S, T> {
    /// Writes `self` into the given vector as a boolean array in little-endian order.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.val.write_bits_le(vec);
    }

    /// Writes `self` into the given vector as a boolean array in big-endian order.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        self.val.write_bits_be(vec);
    }
}
impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> Distribution<&'static MpcBigInteger<F, S, T>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> &'static MpcBigInteger<F, S, T> {
        unimplemented!("MpcBigInteger::BigInteger::Distribution::sample");
    }
}

impl<F: PrimeField<BigInteger = T>, S: FieldShare<F>, T: BigInteger + 'static> From<MpcField<F, S>> for &'static MpcBigInteger<F, S, T> {
    fn from(value: MpcField<F, S>) -> Self {
        match value {
            MpcField::Public(f) => &'static MpcBigInteger::<F, S, T>{
                val: &'static f.to_bigint(),
                _marker: PhantomData,
            },
            MpcField::Shared(f) => {
                unimplemented!("Shared field into BigInteger")
            },
        }
    }
}

// impl<E: PairingEngine, PS: PairingShare<E>, T: BigInteger + 'static> Deref for BigIntegerWrapper<E, PS, T> {
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

// impl<E: PairingEngine, PS: PairingShare<E>, T: BigInteger + 'static> Into<T> for MpcField<E::Fr, PS::FrShare> {
//     fn into(self) -> T {
//         match self {
//             MpcField::Public(f) => f.to_bigint(),
//             MpcField::Shared(f) => {
//                 unimplemented!("Shared field into BigInteger")
//             },
//         }
//     }
// }