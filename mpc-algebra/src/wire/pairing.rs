use serde::{Deserialize, Serialize, Deserializer, Serializer};
use snarkvm_curves::PairingCurve;
use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{Field, FftField, PrimeField, Zero, One, SquareRootField, ToConstraintField, ConstraintFieldError};
use snarkvm_utilities::{
    BigInteger, CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, Compress, Flags, FromBits, FromBytes, SerializationError, ToBits, ToBytes, Uniform, Valid, Validate
};
use std::io::{self, Read, Write};
use core::ops::*;
use derivative::Derivative;
use rand::{Rng, distributions::Distribution};
use std::cmp::Ord;
use std::default::Default;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use zeroize::Zeroize;

use snarkvm_curves::MpcWire;
use crate::{MpcProjectiveGroup, MpcAffineGroup};
use crate::MpcField;
use crate::FieldShare;

use crate::{
    ExtFieldShare,
    {AffProjShare, PairingShare},
    BeaverSource,
    Reveal,
};

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyPairingTripleSource<E, S> {
    _phants: PhantomData<(E, S)>,
}

impl<E: PairingEngine, S: PairingShare<E>>
    BeaverSource<MpcG1Projective<E, S>, MpcG2Projective<E, S>, MpcExtField<E::Fqk, S::FqkShare>>
    for DummyPairingTripleSource<E, S>
{
    #[inline]
    fn triple(
        &mut self,
    ) -> (
        MpcG1Projective<E, S>,
        MpcG2Projective<E, S>,
        MpcExtField<E::Fqk, S::FqkShare>,
    ) {
        let g1 = E::G1Projective::zero();
        let g2 = E::G2Projective::zero();
        (
            MpcG1Projective::from_add_shared(g1.clone()),
            MpcG2Projective::from_add_shared(g2.clone()),
            MpcExtField::from_add_shared(E::pairing(g1, g2)),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (MpcG2Projective<E, S>, MpcG2Projective<E, S>) {
        unimplemented!("No inverses from Pairing triple source")
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq<E::G1Projective>"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG1Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcAffineGroup<E::G1Affine, PS::G1AffineShare>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PairingCurve for MpcG1Affine<E, PS> 
{
    type Engine = MpcPairingEngine<E, PS>;
    type PairWith = MpcG2Affine<E, PS>;
    type PairingResult = MpcExtField<E::Fqk, PS::FqkShare>;
    type Prepared = MpcG1Prep<E, PS>;

    fn prepare(&self) -> Self::Prepared {
        Self::Prepared::from(*self)
    }

    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult {
        MpcPairingEngine::<E, PS>::pairing(*self, *other)
    }
}

impl<E: PairingEngine, PS: PairingShare<E>> PartialEq<MpcG1Projective<E, PS>> for MpcG1Affine<E, PS> {
    fn eq(&self, other: &MpcG1Projective<E, PS>) -> bool {
        match (&self.val, &other.val) {
            (MpcAffineGroup::Shared(_), MpcProjectiveGroup::Shared(_)) => {
                unimplemented!("Shared group comparison")
            },
            (MpcAffineGroup::Public(a), MpcProjectiveGroup::Public(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Projective: PartialEq<E::G1Affine>"),
    Eq(bound = "E::G1Projective: Eq"),
    Hash(bound = "E::G1Projective: Hash")
)]
pub struct MpcG1Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcProjectiveGroup<E::G1Projective, PS::G1ProjectiveShare>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PartialEq<MpcG1Affine<E, PS>> for MpcG1Projective<E, PS> {
    fn eq(&self, other: &MpcG1Affine<E, PS>) -> bool {
        match (&self.val, &other.val) {
            (MpcProjectiveGroup::Shared(_), MpcAffineGroup::Shared(_)) => {
                unimplemented!("Shared group comparison")
            },
            (MpcProjectiveGroup::Public(a), MpcAffineGroup::Public(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Derivative, Eq, PartialEq)]
#[derivative(Clone(bound = ""), Default(bound = "<E::G1Affine as PairingCurve>::Prepared: Default"))]
pub struct MpcG1Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: <E::G1Affine as PairingCurve>::Prepared,
    pub _phants: PhantomData<(E, PS)>,
}

impl<E: PairingEngine, PS: PairingShare<E>> From<MpcG1Affine<E, PS>> for MpcG1Prep<E, PS> {
    fn from(affine: MpcG1Affine<E, PS>) -> Self {
        match affine.val {
            MpcAffineGroup::Public(val) => {
                MpcG1Prep{
                    val: <E::G1Affine as PairingCurve>::Prepared::from(val),
                    _phants: PhantomData,
                }
            }
            MpcAffineGroup::Shared(_) => {
                unimplemented!("MpcG1Prep::from_affine");
            }
        }
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> FromBytes for MpcG1Prep<E, PS> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        unimplemented!("MpcG1Prep::read_le")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> ToBytes for MpcG1Prep<E, PS> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        unimplemented!("MpcG1Prep::write_le")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> CanonicalSerialize for MpcG1Prep<E, PS> {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        unimplemented!("MpcG1Prep::serialize_with_mode")
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        unimplemented!("MpcG1Prep::serialized_size")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> CanonicalDeserialize for MpcG1Prep<E, PS> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        unimplemented!("MpcG1Prep::deserialize_with_mode")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> Valid for MpcG1Prep<E, PS> {
    fn check(&self) -> Result<(), SerializationError> {
        unimplemented!("MpcG1Prep::check")
    }

    fn batch_check<'a>(batch: impl Iterator<Item = &'a Self>) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        unimplemented!("MpcG1Prep::batch_check")
    }
}


#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G2Affine: PartialEq<E::G2Projective>"),
    Eq(bound = "E::G2Affine: Eq"),
    Hash(bound = "E::G2Affine: Hash")
)]
pub struct MpcG2Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcAffineGroup<E::G2Affine, PS::G2AffineShare>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PairingCurve for MpcG2Affine<E, PS> 
{
    type Engine = MpcPairingEngine<E, PS>;
    type PairWith = MpcG1Affine<E, PS>;
    type PairingResult = MpcExtField<E::Fqk, PS::FqkShare>;
    type Prepared = MpcG2Prep<E, PS>;

    fn prepare(&self) -> Self::Prepared {
        Self::Prepared::from(*self)
    }

    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult {
        MpcPairingEngine::<E, PS>::pairing(*other, *self)
    }
}

impl<E: PairingEngine, PS: PairingShare<E>> PartialEq<MpcG2Projective<E, PS>> for MpcG2Affine<E, PS> {
    fn eq(&self, other: &MpcG2Projective<E, PS>) -> bool {
        match (&self.val, &other.val) {
            (MpcAffineGroup::Shared(_), MpcProjectiveGroup::Shared(_)) => {
                unimplemented!("Shared group comparison")
            },
            (MpcAffineGroup::Public(a), MpcProjectiveGroup::Public(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G2Projective: PartialEq<E::G2Affine>"),
    Eq(bound = "E::G2Projective: Eq"),
    Hash(bound = "E::G2Projective: Hash")
)]
pub struct MpcG2Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcProjectiveGroup<E::G2Projective, PS::G2ProjectiveShare>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PartialEq<MpcG2Affine<E, PS>> for MpcG2Projective<E, PS> {
    fn eq(&self, other: &MpcG2Affine<E, PS>) -> bool {
        match (&self.val, &other.val) {
            (MpcProjectiveGroup::Shared(_), MpcAffineGroup::Shared(_)) => {
                unimplemented!("Shared group comparison")
            },
            (MpcProjectiveGroup::Public(a), MpcAffineGroup::Public(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Derivative, Eq, PartialEq)]
#[derivative(Clone(bound = ""), Default(bound = "<E::G2Affine as PairingCurve>::Prepared: Default"))]
pub struct MpcG2Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: <E::G2Affine as PairingCurve>::Prepared,
    pub _phants: PhantomData<(E, PS)>,
}

impl<E: PairingEngine, PS: PairingShare<E>> From<MpcG2Affine<E, PS>> for MpcG2Prep<E, PS> {
    fn from(affine: MpcG2Affine<E, PS>) -> Self {
        match affine.val {
            MpcAffineGroup::Public(val) => {
                MpcG2Prep{
                    val: <E::G2Affine as PairingCurve>::Prepared::from(val),
                    _phants: PhantomData,
                }
            }
            MpcAffineGroup::Shared(_) => {
                unimplemented!("MpcG2Prep::from_affine");
            }
        }
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> FromBytes for MpcG2Prep<E, PS> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        unimplemented!("MpcG2Prep::read_le")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> ToBytes for MpcG2Prep<E, PS> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        unimplemented!("MpcG2Prep::write_le")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> CanonicalSerialize for MpcG2Prep<E, PS> {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        unimplemented!("MpcG2Prep::serialize_with_mode")
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        unimplemented!("MpcG2Prep::serialized_size")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> CanonicalDeserialize for MpcG2Prep<E, PS> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        unimplemented!("MpcG2Prep::deserialize_with_mode")
    }
}
impl<E: PairingEngine, PS: PairingShare<E>> Valid for MpcG2Prep<E, PS> {
    fn check(&self) -> Result<(), SerializationError> {
        unimplemented!("MpcG2Prep::check")
    }

    fn batch_check<'a>(batch: impl Iterator<Item = &'a Self>) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        unimplemented!("MpcG2Prep::batch_check")
    }
}


#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash"),
    Debug(bound = "F: Debug"),
    PartialOrd(bound = "F: PartialOrd"),
    Ord(bound = "F: Ord")
)]
pub struct MpcExtField<F: Field, FS: ExtFieldShare<F>> {
    pub val: MpcField<F, FS::Ext>,
}

/// A wrapper for a pairing engine
#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Default(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Hash(bound = "")
)]
pub struct MpcPairingEngine<E: PairingEngine, PS: PairingShare<E>> {
    _phants: PhantomData<(E, PS)>,
}


impl<E: PairingEngine, PS: PairingShare<E>> PairingEngine for MpcPairingEngine<E, PS> 
where 
    MpcG1Affine<E, PS>: PairingCurve<
            BaseField = MpcField<E::Fq, PS::FqShare>,
            ScalarField = MpcField<E::Fr, PS::FrShare>,
            Projective = MpcG1Projective<E, PS>,
            PairWith = MpcG2Affine<E, PS>,
            Prepared = MpcG1Prep<E, PS>,
            PairingResult = MpcExtField<E::Fqk, PS::FqkShare>,
        > + ToConstraintField<MpcField<E::Fq, PS::FqShare>>,
    MpcG2Affine<E, PS>: PairingCurve<
            BaseField = MpcExtField<E::Fqe, PS::FqeShare>,
            ScalarField = MpcField<E::Fr, PS::FrShare>,
            Projective = MpcG2Projective<E, PS>,
            PairWith = MpcG1Affine<E, PS>,
            Prepared = MpcG2Prep<E, PS>,
            PairingResult = MpcExtField<E::Fqk, PS::FqkShare>,
        > + ToConstraintField<MpcField<E::Fq, PS::FqShare>>,
{
    type Fr = MpcField<E::Fr, PS::FrShare>;
    type Fq = MpcField<E::Fq, PS::FqShare>;
    type Fqe = MpcExtField<E::Fqe, PS::FqeShare>;
    type G1Affine = MpcG1Affine<E, PS>;
    type G1Projective = MpcG1Projective<E, PS>;
    type G2Affine = MpcG2Affine<E, PS>;
    type G2Projective = MpcG2Projective<E, PS>;
    type Fqk = MpcExtField<E::Fqk, PS::FqkShare>;

    fn miller_loop<'a, I>(_i: I) -> Self::Fqk
    where
        // I: (&'a <Self::G1Affine as PairingCurve>::Prepared, &'a <Self::G2Affine as PairingCurve>::Prepared),
        I: IntoIterator<Item = (&'a <Self::G1Affine as PairingCurve>::Prepared, &'a <Self::G2Affine as PairingCurve>::Prepared)>,
    {
        unimplemented!("miller_loop")
        // <Bls12_377 as PairingEngine>::miller_loop(i)
    }

    fn final_exponentiation(_f: &Self::Fqk) -> Option<Self::Fqk> {
        unimplemented!("final_exponentiation")
        // <Bls12_377 as PairingEngine>::final_exponentiation(f)
    }

    /// Performs multiple pairing operations
    #[must_use]
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        let a: Self::G1Affine = p.into();
        let b: Self::G2Affine = q.into();
        let a: Self::G1Projective = a.into();
        let b: Self::G2Projective = b.into();
        if a.is_shared() && b.is_shared() {
            let source = &mut DummyPairingTripleSource::default();
            // x * y = z
            let (x, y, z) = source.triple();
            // x + a
            let xa = (a + x).reveal();
            // y + b
            let yb = (b + y).reveal();
            let xayb: MpcExtField<E::Fqk, PS::FqkShare> =
                MpcExtField::wrap(MpcField::Public(E::pairing(xa, yb)));
            let xay: MpcExtField<E::Fqk, PS::FqkShare> = MpcExtField::wrap(MpcField::Shared(
                <PS::FqkShare as ExtFieldShare<E::Fqk>>::Ext::from_add_shared(E::pairing(
                    xa,
                    y.unwrap_as_public(),
                )),
            ));
            let xyb: MpcExtField<E::Fqk, PS::FqkShare> = MpcExtField::wrap(MpcField::Shared(
                <PS::FqkShare as ExtFieldShare<E::Fqk>>::Ext::from_add_shared(E::pairing(
                    x.unwrap_as_public(),
                    yb,
                )),
            ));
            z / xay / xyb * xayb
        } else {
            MpcExtField::wrap(MpcField::Public(E::pairing(a.reveal(), b.reveal())))
        }
    }
}

macro_rules! impl_pairing_mpc_wrapper {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> Display for $wrap<E, PS> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> ToBytes for $wrap<E, PS> {
            fn write_le<W: Write>(&self, writer: W) -> io::Result<()> {
                self.val.write_le(writer)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> FromBytes for $wrap<E, PS> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Valid for $wrap<E, PS> {
            fn check(&self) -> Result<(), SerializationError> {
                self.val.check()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerialize for $wrap<E, PS> {
            fn serialize_with_mode<W: Write>(
                &self,
                writer: W,
                compress: Compress,
            ) -> Result<(), SerializationError> {
                self.val.serialize_with_mode(writer, compress)
            }
            fn serialized_size(&self, compress: Compress) -> usize {
                self.val.serialized_size(compress)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerializeWithFlags for $wrap<E, PS> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                writer: W,
                flags: F,
            ) -> Result<(), SerializationError> {
                self.val.serialize_with_flags(writer, flags)
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                self.val.serialized_size_with_flags::<F>()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserialize for $wrap<E, PS> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserializeWithFlags for $wrap<E, PS> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Uniform for $wrap<E, PS> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: $wrapped::rand(rng),
                }
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> AddAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn add_assign(&mut self, other: &Self) {
                self.val += &other.val;
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Neg for $wrap<E, PS> {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self::Output {
                Self { val: -self.val }
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> SubAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn sub_assign(&mut self, other: &Self) {
                self.val -= &other.val;
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zero for $wrap<E, PS> {
            #[inline]
            fn zero() -> Self {
                Self {
                    val: $wrapped::zero(),
                }
            }
            #[inline]
            fn is_zero(&self) -> bool {
                self.val.is_zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Sum for $wrap<E, PS> {
            #[inline]
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), Add::add)
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> Sum<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), |x, y| x.add((*y).clone()))
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zeroize for $wrap<E, PS> {
            #[inline]
            fn zeroize(&mut self) {
                self.val.zeroize();
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Default for $wrap<E, PS> {
            #[inline]
            fn default() -> Self {
                Self::zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> MpcWire for $wrap<E, PS> {
            #[inline]
            fn publicize(&mut self) {
                self.val.publicize();
            }
            #[inline]
            fn is_shared(&self) -> bool {
                self.val.is_shared()
            }
        }
        impl_ref_ops!(Sub, SubAssign, sub, sub_assign, $bound1, $bound2, $wrap);
        impl_ref_ops!(Add, AddAssign, add, add_assign, $bound1, $bound2, $wrap);
    };
}
macro_rules! impl_ext_field_wrapper {
    ($wrapped:ident, $wrap:ident) => {
        impl<'a, E: Field, PS: ExtFieldShare<E>> Deserialize<'a> for $wrap<E, PS> {
            #[inline]
            fn deserialize<D: Deserializer<'a>>(_deserializer: D) -> Result<Self, D::Error> {
                unimplemented!("deserialize");
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> Serialize for $wrap<E, PS> {
            #[inline]
            fn serialize<SS: Serializer>(&self, _serializer: SS) -> Result<SS::Ok, SS::Error> {
                unimplemented!("serialize");
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> ToBits for $wrap<E, PS> {
            #[inline]
            fn write_bits_le(&self, _vec: &mut Vec<bool>) {
                unimplemented!("write_bits_le")
            }
            #[inline]
            fn write_bits_be(&self, _vec: &mut Vec<bool>) {
                unimplemented!("write_bits_be")
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> FromBits for $wrap<E, PS> {
            #[inline]
            fn from_bits_le(_bits: &[bool]) -> anyhow::Result<Self> {
                unimplemented!("from_bits_le")
            }
            #[inline]
            fn from_bits_be(_bits: &[bool]) -> anyhow::Result<Self> {
                unimplemented!("from_bits_be")
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> $wrap<E, PS> {
            #[inline]
            pub fn wrap(val: $wrapped<E, PS::Ext>) -> Self {
                Self { val }
            }
            #[inline]
            pub fn new(t: E, shared: bool) -> Self {
                Self::wrap($wrapped::new(t, shared))
            }
            #[inline]
            pub fn from_public(t: E) -> Self {
                Self::wrap($wrapped::from_public(t))
            }
        }

        impl_pairing_mpc_wrapper!($wrapped, Field, ExtFieldShare, BasePrimeField, Ext, $wrap);
    
        impl<'a, E: Field, PS: ExtFieldShare<E>> MulAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn mul_assign(&mut self, other: &Self) {
                self.val *= &other.val;
            }
        }
        impl<'a, E: Field, PS: ExtFieldShare<E>> DivAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn div_assign(&mut self, other: &Self) {
                self.val /= &other.val;
            }
        }
        impl_ref_ops!(Mul, MulAssign, mul, mul_assign, Field, ExtFieldShare, $wrap);
        impl_ref_ops!(Div, DivAssign, div, div_assign, Field, ExtFieldShare, $wrap);
        impl<E: Field, PS: ExtFieldShare<E>> One for $wrap<E, PS> {
            #[inline]
            fn one() -> Self {
                Self {
                    val: $wrapped::one(),
                }
            }
            #[inline]
            fn is_one(&self) -> bool {
                self.val.is_one()
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> Product for $wrap<E, PS> {
            #[inline]
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::one(), Add::add)
            }
        }
        impl<'a, E: Field, PS: ExtFieldShare<E>> Product<&'a $wrap<E, PS>> for $wrap<E, PS> {
            #[inline]
            fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::one(), |x, y| x.add((*y).clone()))
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> Reveal for $wrap<E, PS> {
            type Base = E;
            #[inline]
            fn reveal(self) -> E {
                self.val.reveal()
            }
            #[inline]
            fn from_public(t: E) -> Self {
                Self::wrap($wrapped::from_public(t))
            }
            #[inline]
            fn from_add_shared(t: E) -> Self {
                Self::wrap($wrapped::from_add_shared(t))
            }
            #[inline]
            fn unwrap_as_public(self) -> Self::Base {
                self.val.unwrap_as_public()
            }
            #[inline]
            fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
                Self::wrap($wrapped::king_share(f, rng))
            }
            #[inline]
            fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
                $wrapped::king_share_batch(f, rng)
                    .into_iter()
                    .map(Self::wrap)
                    .collect()
            }
        }
        // from_prim!(bool, Field, ExtFieldShare, $wrap);
        from_prim!(u8, Field, ExtFieldShare, $wrap);
        from_prim!(u16, Field, ExtFieldShare, $wrap);
        from_prim!(u32, Field, ExtFieldShare, $wrap);
        from_prim!(u64, Field, ExtFieldShare, $wrap);
        from_prim!(u128, Field, ExtFieldShare, $wrap);
        impl<F: Field, S: ExtFieldShare<F>> Field for $wrap<F, S> {
            type BasePrimeField = MpcField<F::BasePrimeField, S::Base>;
            fn characteristic<'a>() -> &'a [u64] {
            // fn characteristic() -> u64 {
                unimplemented!("extension_degree")
            }
            fn from_base_prime_field(
                // _b: &[<Self as ark_ff::Field>::BasePrimeField],
                _other: Self::BasePrimeField,
            ) -> Self {
                unimplemented!()
                // assert!(b.len() > 0);
                // let shared = b[0].is_shared();
                // assert!(b.iter().all(|e| e.is_shared() == shared));
                // let base_values = b.iter().map(|e| e.unwrap_as_public()).collect::<Vec<_>>();
                // F::from_base_prime_field_elems(&base_values).map(|val| Self::new(val, shared))
            }
            #[inline]
            fn double(&self) -> Self {
                Self::wrap(self.val * $wrapped::from_public(F::from(2u8)))
            }
            #[inline]
            fn double_in_place(&mut self) {
                self.val *= $wrapped::from_public(F::from(2u8));
            }
            fn from_random_bytes_with_flags<Fl: Flags>(b: &[u8]) -> Option<(Self, Fl)> {
                F::from_random_bytes_with_flags(b).map(|(val, f)| (Self::new(val, true), f))
            }
            #[inline]
            fn square(&self) -> Self {
                self.clone() * self
            }
            #[inline]
            fn square_in_place(&mut self) -> &mut Self {
                *self *= self.clone();
                self
            }
            #[inline]
            fn inverse(&self) -> Option<Self> {
                self.val.inv().map(Self::wrap)
            }
            #[inline]
            fn inverse_in_place(&mut self) -> Option<&mut Self> {
                self.val.inv().map(|i| {
                    self.val = i;
                    self
                })
            }
            fn frobenius_map(&mut self, _: usize) {
                unimplemented!("frobenius_map")
            }
        }

        impl<F: FftField, S: ExtFieldShare<F>> FftField for $wrap<F, S> {
            type FftParameters = F::FftParameters;
            #[inline]
            fn two_adic_root_of_unity() -> Self {
                Self::from_public(F::two_adic_root_of_unity())
            }
            #[inline]
            fn large_subgroup_root_of_unity() -> Option<Self> {
                F::large_subgroup_root_of_unity().map(Self::from_public)
            }
            #[inline]
            fn multiplicative_generator() -> Self {
                Self::from_public(F::multiplicative_generator())
            }
        }

        impl<F: PrimeField, S: ExtFieldShare<F>> std::str::FromStr for $wrap<F, S> {
            type Err = F::Err;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $wrapped::from_str(s).map(Self::wrap)
            }
        }

        impl<F: SquareRootField, S: ExtFieldShare<F>> SquareRootField for $wrap<F, S> {
            fn legendre(&self) -> snarkvm_fields::LegendreSymbol {
                todo!()
            }
            fn sqrt(&self) -> Option<Self> {
                todo!()
            }
            fn sqrt_in_place(&mut self) -> Option<&mut Self> {
                todo!()
            }
        }
    };
}
macro_rules! impl_pairing_curve_wrapper_aff {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $aff_group:ident, $base_field:ident, $base_field_share:ident, $wrap:ident, $proj_wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> $wrap<E, PS> {
            #[inline]
            pub fn new(t: E::$base, shared: bool) -> Self {
                Self {
                    val: $wrapped::new(t, shared),
                }
            }
            #[inline]
            pub fn from_public(t: E::$base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
        }
        impl<'de, E: $bound1, PS: $bound2<E>> Deserialize<'de> for $wrap<E, PS> {
            #[inline]
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                unimplemented!("impl_pairing_curve_wrapper::deserialize")
            }
        }
        impl<'de, E: $bound1, PS: $bound2<E>> Serialize for $wrap<E, PS> {
            #[inline]
            fn serialize<SS: Serializer>(&self, serializer: SS) -> Result<SS::Ok, SS::Error> {
                unimplemented!("impl_pairing_curve_wrapper::serialize")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> ToConstraintField<MpcField<E::Fq, PS::FqShare>> for $wrap<E, PS> 
        {
            #[inline]
            fn to_field_elements(&self) -> Result<Vec<MpcField<E::Fq, PS::FqShare>>, ConstraintFieldError> {
                match &self.val {
                    MpcAffineGroup::Public(a) => a.to_field_elements().map(|v| {
                        v.into_iter()
                            .map(|e| MpcField::from_public(e))
                            .collect()
                    }),
                    MpcAffineGroup::Shared(a) => {
                        unimplemented!("Shared affine group to field elements")
                    },
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Reveal for $wrap<E, PS> {
            type Base = E::$base;
            #[inline]
            fn reveal(self) -> Self::Base {
                self.val.reveal()
            }
            #[inline]
            fn from_public(t: Self::Base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
            #[inline]
            fn from_add_shared(t: Self::Base) -> Self {
                Self {
                    val: $wrapped::from_add_shared(t),
                }
            }
            #[inline]
            fn unwrap_as_public(self) -> Self::Base {
                self.val.unwrap_as_public()
            }
            #[inline]
            fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
                Self {
                    val: $wrapped::king_share(f, rng),
                }
            }
            #[inline]
            fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
                $wrapped::king_share_batch(f, rng)
                    .into_iter()
                    .map(|val| Self { val })
                    .collect()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Display for $wrap<E, PS> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> ToBytes for $wrap<E, PS> {
            fn write_le<W: Write>(&self, writer: W) -> io::Result<()> {
                self.val.write_le(writer)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> FromBytes for $wrap<E, PS> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Valid for $wrap<E, PS> {
            fn check(&self) -> Result<(), SerializationError> {
                self.val.check()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerialize for $wrap<E, PS> {
            fn serialize_with_mode<W: Write>(
                &self,
                writer: W,
                compress: Compress,
            ) -> Result<(), SerializationError> {
                self.val.serialize_with_mode(writer, compress)
            }
            fn serialized_size(&self, compress: Compress) -> usize {
                self.val.serialized_size(compress)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerializeWithFlags for $wrap<E, PS> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                writer: W,
                flags: F,
            ) -> Result<(), SerializationError> {
                self.val.serialize_with_flags(writer, flags)
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                self.val.serialized_size_with_flags::<F>()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserialize for $wrap<E, PS> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserializeWithFlags for $wrap<E, PS> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Uniform for $wrap<E, PS> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: $wrapped::rand(rng),
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Neg for $wrap<E, PS> {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self::Output {
                Self { val: -self.val }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zero for $wrap<E, PS> {
            #[inline]
            fn zero() -> Self {
                Self {
                    val: $wrapped::zero(),
                }
            }
            #[inline]
            fn is_zero(&self) -> bool {
                self.val.is_zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zeroize for $wrap<E, PS> {
            #[inline]
            fn zeroize(&mut self) {
                self.val.zeroize();
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Default for $wrap<E, PS> {
            #[inline]
            fn default() -> Self {
                Self::zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> MpcWire for $wrap<E, PS> {
            #[inline]
            fn publicize(&mut self) {
                self.val.publicize();
            }
            #[inline]
            fn is_shared(&self) -> bool {
                self.val.is_shared()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Mul<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            type Output = $proj_wrap<E, PS>;
            #[inline]
            fn mul(self, other: MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                unimplemented!("$wrap aff mul<MpcField>")
                // Self {
                //     val: self.val.mul(other),
                // }
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> Mul<&'a MpcField<E::Fr, PS::FrShare>>
            for $wrap<E, PS>
        {
            type Output = $proj_wrap<E, PS>;
            #[inline]
            fn mul(self, other: &'a MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                unimplemented!("$wrap aff mul<&MpcField>")
                // Self {
                //     val: self.val.mul(other),
                // }
            }
        }
    };
}

macro_rules! impl_pairing_curve_wrapper_proj {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $proj_group:ident, $base_field:ident, $base_field_share:ident, $wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> $wrap<E, PS> {
            #[inline]
            pub fn new(t: E::$base, shared: bool) -> Self {
                Self {
                    val: $wrapped::new(t, shared),
                }
            }
            #[inline]
            pub fn from_public(t: E::$base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
        }
        impl<'de, E: $bound1, PS: $bound2<E>> Deserialize<'de> for $wrap<E, PS> {
            #[inline]
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                unimplemented!("impl_pairing_curve_wrapper::deserialize")
            }
        }
        impl<'de, E: $bound1, PS: $bound2<E>> Serialize for $wrap<E, PS> {
            #[inline]
            fn serialize<SS: Serializer>(&self, serializer: SS) -> Result<SS::Ok, SS::Error> {
                unimplemented!("impl_pairing_curve_wrapper::serialize")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> ToConstraintField<MpcField<E::Fq, PS::FqShare>> for $wrap<E, PS> {
            #[inline]
            fn to_field_elements(&self) -> Result<Vec<MpcField<E::Fq, PS::FqShare>>, ConstraintFieldError> {
                unimplemented!("proj wrapper to_field_elements")
                // match &self.val {
                //     MpcProjectiveGroup::Public(a) => a.to_field_elements().map(|v| {
                //         v.into_iter()
                //             .map(|e| MpcField::from_public(e))
                //             .collect()
                //     }),
                //     MpcProjectiveGroup::Shared(a) => {
                //         unimplemented!("Shared projective group to field elements")
                //     },
                // }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Reveal for $wrap<E, PS> {
            type Base = E::$base;
            #[inline]
            fn reveal(self) -> Self::Base {
                self.val.reveal()
            }
            #[inline]
            fn from_public(t: Self::Base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
            #[inline]
            fn from_add_shared(t: Self::Base) -> Self {
                Self {
                    val: $wrapped::from_add_shared(t),
                }
            }
            #[inline]
            fn unwrap_as_public(self) -> Self::Base {
                self.val.unwrap_as_public()
            }
            #[inline]
            fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
                Self {
                    val: $wrapped::king_share(f, rng),
                }
            }
            #[inline]
            fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
                $wrapped::king_share_batch(f, rng)
                    .into_iter()
                    .map(|val| Self { val })
                    .collect()
            }
        }

        impl_pairing_mpc_wrapper!($wrapped, $bound1, $bound2, $base, $share, $wrap);

        impl<E: $bound1, PS: $bound2<E>> Mul<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            type Output = Self;
            #[inline]
            fn mul(self, other: MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                unimplemented!("$wrap proj mul<MpcField>")
                // Self {
                //     val: self.val.mul(other),
                // }
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> Mul<&'a MpcField<E::Fr, PS::FrShare>>
            for $wrap<E, PS>
        {
            type Output = Self;
            #[inline]
            fn mul(self, other: &'a MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                unimplemented!("$wrap proj mul<&MpcField>")
                // Self {
                //     val: self.val.mul(other),
                // }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> MulAssign<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            #[inline]
            fn mul_assign(&mut self, other: MpcField<E::Fr, PS::FrShare>) {
                self.val.mul_assign(other);
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> MulAssign<&'a MpcField<E::Fr, PS::FrShare>>
            for $wrap<E, PS>
        {
            #[inline]
            fn mul_assign(&mut self, other: &'a MpcField<E::Fr, PS::FrShare>) {
                self.val.mul_assign(other);
            }
        }
    };
}

impl_pairing_curve_wrapper_aff!(
    MpcAffineGroup,
    PairingEngine,
    PairingShare,
    G1Affine,
    G1AffineShare,
    AffineCurve,
    Fq,
    FqShare,
    MpcG1Affine,
    MpcG1Projective
);
impl_pairing_curve_wrapper_proj!(
    MpcProjectiveGroup,
    PairingEngine,
    PairingShare,
    G1Projective,
    G1ProjectiveShare,
    ProjectiveCurve,
    Fq,
    FqShare,
    MpcG1Projective
);
impl_pairing_curve_wrapper_aff!(
    MpcAffineGroup,
    PairingEngine,
    PairingShare,
    G2Affine,
    G2AffineShare,
    AffineCurve,
    Fqe,
    FqeShare,
    MpcG2Affine,
    MpcG2Projective
);
impl_pairing_curve_wrapper_proj!(
    MpcProjectiveGroup,
    PairingEngine,
    PairingShare,
    G2Projective,
    G2ProjectiveShare,
    ProjectiveCurve,
    Fqe,
    FqeShare,
    MpcG2Projective
);
impl_ext_field_wrapper!(MpcField, MpcExtField);

macro_rules! impl_aff_proj {
    ($w_aff:ident, $w_pro:ident, $aff:ident, $pro:ident, $g_name:ident, $w_base:ident, $base:ident, $base_share:ident, $share_aff:ident, $share_proj:ident) => {
        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_pro<E, PS>> for $w_aff<E, PS> {
            #[inline]
            fn from(o: $w_pro<E, PS>) -> Self {
                // map(public_fn, private_fn)
                Self {
                    val: o.val.map(|s| s.into(), PS::$g_name::sh_proj_to_aff),
                }
            }
        }
        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_pro<E, PS> {
            #[inline]
            fn from(o: $w_aff<E, PS>) -> Self {
                Self {
                    val: o.val.map(|s| s.into(), PS::$g_name::sh_aff_to_proj),
                }
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> AffineCurve for $w_aff<E, PS> 
        {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
            type Coordinates = <<E as PairingEngine>::$aff as AffineCurve>::Coordinates;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Projective = $w_pro<E, PS>;
            #[inline]
            fn prime_subgroup_generator() -> Self {
                Self::from_public(E::$aff::prime_subgroup_generator())
            }
            fn from_random_bytes(_: &[u8]) -> Option<Self> {
                todo!("AffineCurve::from_random_bytes")
            }
            fn mul_by_cofactor_to_projective(&self) -> <Self as AffineCurve>::Projective {
                todo!("AffineCurve::mul_by_cofactor_to_projective")
            }
            fn mul_by_cofactor_inv(&self) -> Self {
                todo!("AffineCurve::mul_by_cofactor_inv")
            }
            fn from_coordinates(coordinates: Self::Coordinates) -> Option<Self> {
                todo!("AffineCurve::from_coordinates")
            }
            fn from_coordinates_unchecked(coordinates: Self::Coordinates) -> Self {
                todo!("AffineCurve::from_coordinates_unchecked")
            }
            fn cofactor() -> &'static [u64] {
                todo!("AffineCurve::cofactor")
            }
            fn from_x_coordinate(_x: Self::BaseField, _greatest: bool) -> Option<Self> {
                todo!("AffineCurve::from_x_coordinate")
            }
            fn pair_from_x_coordinate(x: Self::BaseField) -> Option<(Self, Self)> {
                todo!("AffineCurve::pair_from_x_coordinate")
            }
            fn from_y_coordinate(_y: Self::BaseField, _positive: bool) -> Option<Self> {
                todo!("AffineCurve::from_y_coordinate")
            }
            fn to_projective(&self) -> Self::Projective {
                todo!("AffineCurve::to_projective")
            }
            fn mul_bits(&self, bits: impl Iterator<Item = bool>) -> Self::Projective {
                let mut output = Self::Projective::zero();
                for bit in bits {
                    output.double_in_place();
                    if bit {
                        output.add_assign_mixed(self);
                    }
                }
                output
            }
            fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
                todo!("AffineCurve::is_in_correct_subgroup_assuming_on_curve")
            }
            fn to_x_coordinate(&self) -> Self::BaseField {
                todo!("AffineCurve::to_x_coordinate")
            }
            fn to_y_coordinate(&self) -> Self::BaseField {
                todo!("AffineCurve::to_y_coordinate")
            }
            fn is_on_curve(&self) -> bool {
                todo!("AffineCurve::is_on_curve")
            }
            fn batch_add_loop_1(a: &mut Self, b: &mut Self, _half: &Self::BaseField, inversion_tmp: &mut Self::BaseField) {
                todo!("AffineCurve::batch_add_loop_1")
            }
            fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField) {
                todo!("AffineCurve::batch_add_loop_2")
            }
        }
        impl<E: PairingEngine, PS: PairingShare<E>> ProjectiveCurve for $w_pro<E, PS> 
        {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Affine = $w_aff<E, PS>;
            #[inline]
            fn prime_subgroup_generator() -> Self {
                Self::from_public(E::$pro::prime_subgroup_generator())
            }
            fn batch_normalization(_elems: &mut [Self]) {
                todo!("ProjectiveCurve::batch_normalization")
            }
            fn is_normalized(&self) -> bool {
                todo!("ProjectiveCurve::is_normalized")
            }
            fn double_in_place(&mut self) {
                match self.val {
                    MpcProjectiveGroup::Shared(ref mut a) => {
                        todo!("ProjectiveCurve::double_in_place")
                    },
                    MpcProjectiveGroup::Public(ref mut a) => a.double_in_place(),
                }

            }
            fn double(&self) -> Self {
                todo!("ProjectiveCurve::double")
            }
            fn to_affine(&self) -> Self::Affine {
                self.clone().into()
            }
            fn add_assign_mixed(&mut self, o: &<Self as ProjectiveCurve>::Affine) {
                let new_self = match (&self.val, &o.val) {
                    (MpcProjectiveGroup::Shared(a), MpcAffineGroup::Shared(b)) => {
                        MpcProjectiveGroup::Shared(PS::$g_name::add_sh_proj_sh_aff(a.clone(), b))
                    }
                    (MpcProjectiveGroup::Shared(a), MpcAffineGroup::Public(b)) => {
                        MpcProjectiveGroup::Shared(PS::$g_name::add_sh_proj_pub_aff(a.clone(), b))
                    }
                    (MpcProjectiveGroup::Public(a), MpcAffineGroup::Shared(b)) => {
                        MpcProjectiveGroup::Shared(PS::$g_name::add_pub_proj_sh_aff(a, b.clone()))
                    }
                    (MpcProjectiveGroup::Public(a), MpcAffineGroup::Public(b)) => MpcProjectiveGroup::Public({
                        let mut a = a.clone();
                        a.add_assign_mixed(b);
                        a
                    }),
                };
                self.val = new_self;
            }
        }
    };
}

impl_aff_proj!(
    MpcG1Affine,
    MpcG1Projective,
    G1Affine,
    G1Projective,
    G1,
    MpcField,
    Fq,
    FqShare,
    G1AffineShare,
    G1ProjectiveShare
);
impl_aff_proj!(
    MpcG2Affine,
    MpcG2Projective,
    G2Affine,
    G2Projective,
    G2,
    MpcExtField,
    Fqe,
    FqeShare,
    G2AffineShare,
    G2ProjectiveShare
);
