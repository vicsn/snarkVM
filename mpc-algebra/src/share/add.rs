#![macro_use]
use derivative::Derivative;
use rand::Rng;

use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{Field, poly_stub};
use snarkvm_utilities::bytes::{FromBytes, ToBytes};
use snarkvm_utilities::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, Compress, Flags, SerializationError, Uniform, Valid, Validate
};

use std::borrow::Cow;
use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use mpc_net::{MpcNet, MpcMultiNet as Net};
use crate::channel::MpcSerNet;

use crate::{
    {ExtFieldShare, FieldShare},
    {ProjectiveGroupShare, AffineGroupShare},
    {AffProjShare, PairingShare},
    BeaverSource,
    Reveal,
};
use crate::msm::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveFieldShare<T> {
    pub val: T,
}

impl<F: Field> AdditiveFieldShare<F> {
    fn poly_share<'a>(
        p: poly_stub::DenseOrSparsePolynomial<Self>,
    ) -> snarkvm_fft::fft::Polynomial<'a, F> {
        match p {
            Ok(p) => snarkvm_fft::fft::Polynomial::Dense(Cow::Owned(
                Self::d_poly_share(p),
            )),
            Err(p) => snarkvm_fft::fft::Polynomial::Sparse(Cow::Owned(
                Self::s_poly_share(p),
            )),
        }
    }
    fn d_poly_share(p: poly_stub::MpcDensePolynomial<Self>) -> snarkvm_fft::fft::DensePolynomial<F> {
        snarkvm_fft::fft::DensePolynomial::from_coefficients_vec(
            p.into_iter().map(|s| s.val).collect(),
        )
    }
    fn s_poly_share(p: poly_stub::MpcSparsePolynomial<Self>) -> snarkvm_fft::fft::SparsePolynomial<F> {
        snarkvm_fft::fft::SparsePolynomial::from_coefficients(
            p.into_iter().map(|(i, s)| (i, s.val)),
        )
    }
    fn poly_share2<'a>(
        p: poly_stub::DenseOrSparsePolynomial<F>,
    ) -> snarkvm_fft::fft::Polynomial<'a, F> {
        match p {
            Ok(p) => snarkvm_fft::fft::Polynomial::Dense(Cow::Owned(
                snarkvm_fft::fft::DensePolynomial::from_coefficients_vec(p),
            )),
            Err(p) => snarkvm_fft::fft::Polynomial::Sparse(Cow::Owned(
                snarkvm_fft::fft::SparsePolynomial::from_coefficients_slice(&p.into_iter().collect::<Vec<_>>()),
            )),
        }
    }
    fn d_poly_unshare(p: snarkvm_fft::fft::DensePolynomial<F>) -> poly_stub::MpcDensePolynomial<Self> {
        p.coeffs
            .into_iter()
            .map(|s| Self::from_add_shared(s))
            .collect()
    }
}

impl<F: Field> Reveal for AdditiveFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        Net::broadcast(&self.val).into_iter().sum()
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if Net::am_king() { f } else { F::zero() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
    fn unwrap_as_public(self) -> F {
        self.val
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<F> = (0..(Net::n_parties()-1)).map(|_| F::rand(rng)).collect();
        let sum_r: F = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> =
            (0..(Net::n_parties()-1)).map(|_| {
            (0..f.len()).map(|_| {
                F::rand(rng)
            }).collect()
        }).collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len()).map(|i| {
            f[i] - &rs.iter().map(|r| &r[i]).sum()
        }).collect();
        rs.push(final_shares);
        Net::recv_from_king(if Net::am_king() { Some(rs) } else {None}).into_iter().map(Self::from_add_shared).collect()
    }
}

impl<F: Field> FieldShare<F> for AdditiveFieldShare<F> {
    fn raw_share(&self) -> F {
        self.val
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len()).map(|i| all_vals.iter().map(|v| v[i]).sum()).collect()
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= &other.val;
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.val *= other;
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        if Net::am_king() {
            self.val += other;
        }
        self
    }

    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<F>,
    ) -> anyhow::Result<(poly_stub::MpcDensePolynomial<Self>, poly_stub::MpcDensePolynomial<Self>)> {
        let num = Self::poly_share(num);
        let den = Self::poly_share2(den);
        let (q, r) = num.divide_with_q_and_r(&den).unwrap();
        Ok((Self::d_poly_unshare(q), Self::d_poly_unshare(r)))
    }
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "P: Default"),
    Clone(bound = "P: Clone"),
    Copy(bound = "P: Copy"),
    PartialEq(bound = "P: PartialEq<P::Affine>"),
    Eq(bound = "P: Eq"),
    // PartialOrd(bound = "P: PartialOrd"),
    // Ord(bound = "P: Ord"),
    Hash(bound = "P: Hash")
)]
pub struct AdditiveProjectiveShare<P: ProjectiveCurve, M> {
    pub val: P,
    _phants: PhantomData<M>,
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "A: Default"),
    Clone(bound = "A: Clone"),
    Copy(bound = "A: Copy"),
    PartialEq(bound = "A: PartialEq<A::Projective>"),
    Eq(bound = "A: Eq"),
    // PartialOrd(bound = "A: PartialOrd"),
    // Ord(bound = "A: Ord"),
    Hash(bound = "A: Hash")
)]
pub struct AdditiveAffineShare<A: AffineCurve, M> {
    pub val: A,
    _phants: PhantomData<M>,
}

impl<G: ProjectiveCurve, M> Reveal for AdditiveProjectiveShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        Net::broadcast(&self.val).into_iter().sum::<G>()
    }
    fn from_public(f: G) -> Self {
        Self {
            val: if Net::am_king() { f } else { G::zero() },
            _phants: PhantomData::default(),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            val: f,
            _phants: PhantomData::default(),
        }
    }
    fn unwrap_as_public(self) -> G {
        self.val
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<Self::Base> = (0..(Net::n_parties()-1)).map(|_| Self::Base::rand(rng)).collect();
        let sum_r: Self::Base = r.iter().cloned().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> =
            (0..(Net::n_parties()-1)).map(|_| {
            (0..f.len()).map(|_| {
                Self::Base::rand(rng)
            }).collect()
        }).collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len()).map(|i| {
            f[i] - rs.iter().map(|r| r[i]).sum::<Self::Base>()
        }).collect();
        rs.push(final_shares);
        Net::recv_from_king(if Net::am_king() { Some(rs) } else {None}).into_iter().map(Self::from_add_shared).collect()
    }
}
impl<G: ProjectiveCurve, M: Msm<G, G::ScalarField>> ProjectiveGroupShare<G> for AdditiveProjectiveShare<G, M> {
    type FieldShare = AdditiveFieldShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let self_vec: Vec<G> = selfs.into_iter().map(|s| s.val).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len()).map(|i| all_vals.iter().map(|v| v[i]).sum()).collect()
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= &other.val;
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.val *= *scalar;
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
        base *= scalar.val;
        Self {
            val: base,
            _phants: PhantomData::default(),
        }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.val += *other;
        }
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
        Self::from_add_shared(M::msm(bases, &scalars))
    }
}
impl<G: AffineCurve, M> Reveal for AdditiveAffineShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        Net::broadcast(&self.val).into_iter().map(|v|v.into()).sum::<G::Projective>().into()
    }
    fn from_public(f: G) -> Self {
        Self {
            val: if Net::am_king() { f } else { G::zero() },
            _phants: PhantomData::default(),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            val: f,
            _phants: PhantomData::default(),
        }
    }
    fn unwrap_as_public(self) -> G {
        self.val
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<<G as AffineCurve>::Projective> = (0..(Net::n_parties()-1)).map(|_| <G as AffineCurve>::Projective::rand(rng)).collect();
        let sum_r: <G as AffineCurve>::Projective = r.iter().cloned().sum();
        r.push(Into::<<G as AffineCurve>::Projective>::into(f) - sum_r);
        // Convert shares back to Self::Base
        let r: Vec<Self::Base> = r.into_iter().map(|r| r.into()).collect();
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r.into()) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<<G as AffineCurve>::Projective>> =
            (0..(Net::n_parties()-1)).map(|_| {
            (0..f.len()).map(|_| {
                <G as AffineCurve>::Projective::rand(rng)
            }).collect()
        }).collect();
        let final_shares: Vec<<G as AffineCurve>::Projective> = (0..rs[0].len()).map(|i| {
            Into::<<G as AffineCurve>::Projective>::into(f[i]) - rs.iter().map(|r| r[i]).sum::<<G as AffineCurve>::Projective>()
        }).collect();
        rs.push(final_shares);
        // Convert shares back to Self::Base
        let mut rs_base = Vec::<Vec<Self::Base>>::with_capacity(rs.len());
        for rs in rs.iter() {
            rs_base.push(rs.iter().map(|r| (*r).into()).collect());
        }
        Net::recv_from_king(if Net::am_king() { Some(rs_base) } else {None}).into_iter().map(Self::from_add_shared).collect()
    }
}
impl<G: AffineCurve, M: Msm<G, G::ScalarField>> AffineGroupShare<G> for AdditiveAffineShare<G, M> {
    type FieldShare = AdditiveFieldShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let self_vec: Vec<<G as AffineCurve>::Projective> = selfs.into_iter().map(|s| s.val.into()).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len()).map(|i| all_vals.iter().map(|v| v[i]).sum::<<G as AffineCurve>::Projective>().into()).collect()
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val = (Into::<<G as AffineCurve>::Projective>::into(self.val) + Into::<<G as AffineCurve>::Projective>::into(other.val)).into();
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val = (Into::<<G as AffineCurve>::Projective>::into(self.val) - Into::<<G as AffineCurve>::Projective>::into(other.val)).into();
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.val = (self.val * *scalar).into();
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
        base = (base * scalar.val).into();
        Self {
            val: base,
            _phants: PhantomData::default(),
        }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.val = (Into::<<G as AffineCurve>::Projective>::into(self.val) + Into::<<G as AffineCurve>::Projective>::into(*other)).into();
        }
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
        Self::from_add_shared(M::msm(bases, &scalars))
    }
}

macro_rules! impl_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write_le<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound> FromBytes for $share<T> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound> Valid for $share<T> {
            fn check(&self) -> Result<(), SerializationError> {
                unimplemented!("check")
            }
        }
        impl<T: $bound> CanonicalSerialize for $share<T> {
            fn serialize_with_mode<W: Write>(&self, _writer: W, _compress: Compress) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_mode")
            }
            fn serialized_size(&self, _compress: Compress) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound> CanonicalSerializeWithFlags for $share<T> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound> CanonicalDeserialize for $share<T> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<T: $bound> CanonicalDeserializeWithFlags for $share<T> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound> Uniform for $share<T> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::from_add_shared(<T as Uniform>::rand(rng))
            }
        }
    };
}
macro_rules! impl_basics_2_param {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
            }
        }
        impl<T: $bound, M> ToBytes for $share<T, M> {
            fn write_le<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound, M> FromBytes for $share<T, M> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, M> Valid for $share<T, M> {
            fn check(&self) -> Result<(), SerializationError> {
                unimplemented!("check")
            }
        }        
        impl<T: $bound, M> CanonicalSerialize for $share<T, M> {
            fn serialize_with_mode<W: Write>(&self, _writer: W, _compress: Compress) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_mode")
            }
            fn serialized_size(&self, _compress: Compress) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound, M> CanonicalSerializeWithFlags for $share<T, M> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound, M> CanonicalDeserialize for $share<T, M> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<T: $bound, M> CanonicalDeserializeWithFlags for $share<T, M> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, M> Uniform for $share<T, M> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Reveal::from_add_shared(<T as Uniform>::rand(rng))
            }
        }
    };
}

impl_basics!(AdditiveFieldShare, Field);
impl_basics_2_param!(AdditiveProjectiveShare, ProjectiveCurve);
impl_basics_2_param!(AdditiveAffineShare, AffineCurve);

// impl<F: Field> Field for AdditiveFieldShare<F> {
// }

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct AdditiveExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for AdditiveExtFieldShare<F> {
    type Ext = AdditiveFieldShare<F>;
    type Base = AdditiveFieldShare<F::BasePrimeField>;
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MulFieldShare<T> {
    pub val: T,
}

impl<F: Field> Reveal for MulFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        Net::broadcast(&self.val).into_iter().product()
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if Net::am_king() { f } else { F::one() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
    fn unwrap_as_public(self) -> F {
        self.val
    }
}

impl<F: Field> FieldShare<F> for MulFieldShare<F> {
    fn raw_share(&self) -> F {
        self.val
    }

    fn map_homo<FF: Field, SS: FieldShare<FF>, Fun: Fn(F) -> FF>(self, _f: Fun) -> SS {
        unimplemented!()
    }
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len()).map(|i| all_vals.iter().map(|v| &v[i]).product()).collect()
    }

    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        println!("MulFieldShare::scale");
        if Net::am_king() {
            self.val *= other;
        }
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        Self {
            val: self.val * other.val,
        }
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.val *= y.val;
        }
        xs
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(mut self, _source: &mut S) -> Self {
        self.val = self.val.inverse().unwrap();
        self
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
        xs.into_iter().map(|x| x.inv(source)).collect()
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for MulExtFieldShare<F> {
    type Ext = MulFieldShare<F>;
    type Base = MulFieldShare<F::BasePrimeField>;
}

impl_basics!(MulFieldShare, Field);

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = AdditiveFieldShare<E::Fr>;
            type AffineShare = AdditiveAffineShare<E::$affine, crate::msm::AffineMsm<E::$affine>>;
            type ProjectiveShare =
                AdditiveProjectiveShare<E::$proj, crate::msm::ProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                g.map_homo(|s| s.into())
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                g.map_homo(|s| s.into())
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o.val);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                if Net::am_king() {
                    a.val.add_assign_mixed(&o);
                }
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(AdditiveG1Share, G1Affine, G1Projective);
groups_share!(AdditiveG2Share, G2Affine, G2Projective);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct AdditivePairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for AdditivePairingShare<E> {
    type FrShare = AdditiveFieldShare<E::Fr>;
    type FqShare = AdditiveFieldShare<E::Fq>;
    type FqeShare = AdditiveExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = MulExtFieldShare<E::Fqk>;
    type G1AffineShare = AdditiveAffineShare<E::G1Affine, crate::msm::AffineMsm<E::G1Affine>>;
    type G2AffineShare = AdditiveAffineShare<E::G2Affine, crate::msm::AffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        AdditiveProjectiveShare<E::G1Projective, crate::msm::ProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        AdditiveProjectiveShare<E::G2Projective, crate::msm::ProjectiveMsm<E::G2Projective>>;
    type G1 = AdditiveG1Share<E>;
    type G2 = AdditiveG2Share<E>;
}
