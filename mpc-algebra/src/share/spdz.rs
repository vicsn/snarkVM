#![macro_use]
use derivative::Derivative;
use rand::Rng;

use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_fields::poly_stub;
use snarkvm_utilities::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError, Compress, Uniform, FromBytes, ToBytes, Validate, Valid,
};
use std::collections::BTreeMap;


use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use mpc_net::{MpcNet, MpcMultiNet as Net};
use crate::channel::{can_cheat, MpcSerNet};

use super::add::{AdditiveFieldShare, AdditiveProjectiveShare, AdditiveAffineShare, MulFieldShare};
use crate::{
    {ExtFieldShare, FieldShare},
    {ProjectiveGroupShare, AffineGroupShare},
    {AffProjShare, PairingShare},
    BeaverSource,
    Reveal,
};
use super::msm::*;
use super::PanicBeaverSource;

#[inline]
pub fn mac_share<F: Field>() -> F {
    if Net::am_king() {
        F::one()
    } else {
        F::zero()
    }
}

#[inline]
/// A huge cheat. Useful for importing shares.
pub fn mac<F: Field>() -> F {
    if can_cheat() {
        F::one()
    } else {
        panic!("Attempted to grab the MAC secret while cheating was not allowed")
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpdzFieldShare<T> {
    sh: AdditiveFieldShare<T>,
    mac: AdditiveFieldShare<T>,
}

macro_rules! impl_basics_spdz {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.sh)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.sh)
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
                Self::from_public(<T as Uniform>::rand(rng))
            }
        }
    };
}
impl_basics_spdz!(SpdzFieldShare, Field);

impl<F: Field> Reveal for SpdzFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let vals: Vec<F> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = vals.iter().sum();
        let dx_t: F = mac_share::<F>() * x - self.mac.val;
        let all_dx_ts: Vec<F> = Net::atomic_broadcast(&dx_t);
        let sum: F = all_dx_ts.iter().sum();
        assert!(sum.is_zero());
        x
    }
    fn from_public(f: F) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared(f * mac_share::<F>()),
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared(f * mac::<F>()),
        }
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<F> = (0..(Net::n_parties()-1)).map(|_| F::rand(rng)).collect();
        let sum_r: F = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        println!("Called king_share_batch");
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

impl<F: Field> FieldShare<F> for SpdzFieldShare<F> {
    fn raw_share(&self) -> F {
        self.sh.val
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let (s_vals, macs): (Vec<F>, Vec<F>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let n = s_vals.len();
        let all_vals = Net::broadcast(&s_vals);
        let vals: Vec<F> =
            (0..n).map(|i| all_vals.iter().map(|v| v[i]).sum()).collect();
        let dx_ts: Vec<F> =
            macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| mac_share::<F>() * val - mac)
            .collect();
        let all_dx_ts: Vec<Vec<F>> = Net::atomic_broadcast(&dx_ts);
        for i in 0..n {
            let sum: F = all_dx_ts.iter().map(|dx_ts| &dx_ts[i]).sum();
            assert!(sum.is_zero());
        }
        vals
    }
    fn add(&mut self, other: &Self) -> &mut Self {
        self.sh.add(&other.sh);
        self.mac.add(&other.mac);
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.sh.sub(&other.sh);
        self.mac.sub(&other.mac);
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.sh.scale(other);
        self.mac.scale(other);
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        self.sh.shift(other);
        self.mac.val += mac_share::<F>() * other;
        self
    }

    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<F>,
    ) -> anyhow::Result<(poly_stub::MpcDensePolynomial<Self>, poly_stub::MpcDensePolynomial<Self>)> {
        let (num_sh, num_mac) = match num {
            Ok(dense) => {
                let (num_sh, num_mac): (Vec<_>, Vec<_>) =
                    dense.into_iter().map(|s| (s.sh, s.mac)).unzip();
                (Ok(num_sh), Ok(num_mac))
            }
            Err(sparse) => {
                let (num_sh, num_mac): (BTreeMap<_,_>, BTreeMap<_,_>) = sparse
                    .into_iter()
                    .map(|(i, s)| ((i, s.sh), (i, s.mac)))
                    .unzip();
                (Err(num_sh), Err(num_mac))
            }
        };
        let (q_sh, r_sh) = AdditiveFieldShare::univariate_div_qr(num_sh, den.clone()).unwrap();
        let (q_mac, r_mac) = AdditiveFieldShare::univariate_div_qr(num_mac, den).unwrap();
        Ok((
            q_sh.into_iter()
                .zip(q_mac)
                .map(|(sh, mac)| Self { sh, mac })
                .collect(),
            r_sh.into_iter()
                .zip(r_mac)
                .map(|(sh, mac)| Self { sh, mac })
                .collect(),
        ))
    }
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "T: Default"),
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    // PartialOrd(bound = "T: PartialOrd"),
    // Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct SpdzProjectiveShare<T: ProjectiveCurve, M> {
    sh: AdditiveProjectiveShare<T, M>,
    mac: AdditiveProjectiveShare<T, M>,
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "T: Default"),
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    // PartialOrd(bound = "T: PartialOrd"),
    // Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct SpdzAffineShare<T: AffineCurve, M> {
    pub sh: AdditiveAffineShare<T, M>,
    pub mac: AdditiveAffineShare<T, M>,
}

impl<G: ProjectiveCurve, M> Reveal for SpdzProjectiveShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        let vals: Vec<G> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: G = vals.into_iter().sum();
        let dx_t: G = {
            let mut t = x.clone();
            t *= mac_share::<G::ScalarField>();
            t - self.mac.val
        };
        let all_dx_ts: Vec<G> = Net::atomic_broadcast(&dx_t);
        let sum: G = all_dx_ts.into_iter().sum();
        assert!(sum.is_zero());
        x
    }
    fn from_public(f: G) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared({
                let mut t = f;
                t *= mac_share::<G::ScalarField>();
                t
            }),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared({
                let mut t = f;
                t *= mac::<G::ScalarField>();
                t
            }),
        }
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<Self::Base> = (0..(Net::n_parties()-1)).map(|_| Self::Base::rand(rng)).collect();
        let sum_r: Self::Base = r.iter().cloned().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r.into()) } else { None }))
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

impl<G: ProjectiveCurve, M: Msm<G, G::ScalarField>> ProjectiveGroupShare<G> for SpdzProjectiveShare<G, M> {
    type FieldShare = SpdzFieldShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let (s_vals, macs): (Vec<G>, Vec<G>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let n = s_vals.len();
        let all_vals = Net::broadcast(&s_vals);
        let vals: Vec<G> =
            (0..n).map(|i| all_vals.iter().map(|v| v[i]).sum()).collect();
        let dx_ts: Vec<G> =
            macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| val.mul(mac_share::<G::ScalarField>()) - *mac)
            .collect();
        let all_dx_ts: Vec<Vec<G>> = Net::atomic_broadcast(&dx_ts);
        for i in 0..n {
            let sum: G = all_dx_ts.iter().map(|dx_ts| dx_ts[i]).sum();
            assert!(sum.is_zero());
        }
        vals
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.sh.add(&other.sh);
        self.mac.add(&other.mac);
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.sh.sub(&other.sh);
        self.mac.sub(&other.mac);
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.sh.scale_pub_scalar(scalar);
        self.mac.scale_pub_scalar(scalar);
        self
    }

    fn scale_pub_group(base: G, scalar: &Self::FieldShare) -> Self {
        let sh = AdditiveProjectiveShare::scale_pub_group(base, &scalar.sh);
        let mac = AdditiveProjectiveShare::scale_pub_group(base, &scalar.mac);
        Self { sh, mac }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.sh.shift(other);
        }
        let mut other = other.clone();
        other *= mac_share::<G::ScalarField>();
        self.mac.val += other;
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let shares: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let macs: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let sh = AdditiveProjectiveShare::from_add_shared(M::msm(bases, &shares));
        let mac = AdditiveProjectiveShare::from_add_shared(M::msm(bases, &macs));
        Self { sh, mac }
    }
}
impl<G: AffineCurve, M> Reveal for SpdzAffineShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        let vals: Vec<G> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: <G as AffineCurve>::Projective = vals.iter().map(|&v|Into::<<G as AffineCurve>::Projective>::into(v)).sum();
        let dx_t: <G as AffineCurve>::Projective = {
            let mut t = x.clone();
            t *= mac_share::<G::ScalarField>();
            t - Into::<<G as AffineCurve>::Projective>::into(self.mac.val)
        };
        let all_dx_ts: Vec<<G as AffineCurve>::Projective> = Net::atomic_broadcast(&dx_t);
        let sum: G = all_dx_ts.into_iter().sum::<<G as AffineCurve>::Projective>().into();
        assert!(sum.is_zero());
        x.into()
    }
    fn from_public(f: G) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared({
                (f * mac_share::<G::ScalarField>()).into()
            }),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared({
                (f * mac::<G::ScalarField>()).into()
            }),
        }
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<<G as AffineCurve>::Projective> = (0..(Net::n_parties()-1)).map(|_| <G as AffineCurve>::Projective::rand(rng)).collect();
        let sum_r: <G as AffineCurve>::Projective = r.iter().cloned().sum();
        r.push(Into::<<G as AffineCurve>::Projective>::into(f) - sum_r);
        // Convert to Affine
        let r = r.into_iter().map(Into::into).collect();
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
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
        // Convert back to Affine
        let rs = rs.into_iter().map(|r| r.into_iter().map(Into::<G>::into).collect::<Vec<_>>()).collect::<Vec<_>>();
        Net::recv_from_king(if Net::am_king() { Some(rs) } else {None}).into_iter().map(Self::from_add_shared).collect()
    }
}

impl<G: AffineCurve, M: Msm<G, G::ScalarField>> AffineGroupShare<G> for SpdzAffineShare<G, M> {
    type FieldShare = SpdzFieldShare<G::ScalarField>;

    fn raw_share(&self) -> G {
        println!("SpdzAffineShare::raw_share");
        self.sh.raw_share()
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let (s_vals, macs): (Vec<<G as AffineCurve>::Projective>, Vec<<G as AffineCurve>::Projective>) =
            selfs.into_iter().map(|s| (Into::<<G as AffineCurve>::Projective>::into(s.sh.val), Into::<<G as AffineCurve>::Projective>::into(s.mac.val))).unzip();
        let n = s_vals.len();
        let all_vals = Net::broadcast(&s_vals);
        let vals: Vec<G> =
            (0..n).map(|i| all_vals.iter().map(|v| v[i]).sum::<<G as AffineCurve>::Projective>().into()).collect();
        let dx_ts: Vec<<G as AffineCurve>::Projective> =
            macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| val.mul(mac_share::<G::ScalarField>()) - *mac)
            .collect();
        let all_dx_ts: Vec<Vec<<G as AffineCurve>::Projective>> = Net::atomic_broadcast(&dx_ts);
        for i in 0..n {
            let sum: G = all_dx_ts.iter().map(|dx_ts| dx_ts[i]).sum::<<G as AffineCurve>::Projective>().into();
            assert!(sum.is_zero());
        }
        vals
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.sh.add(&other.sh);
        self.mac.add(&other.mac);
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.sh.sub(&other.sh);
        self.mac.sub(&other.mac);
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.sh.scale_pub_scalar(scalar);
        self.mac.scale_pub_scalar(scalar);
        self
    }

    fn scale_pub_group(base: G, scalar: &Self::FieldShare) -> Self {
        let sh = AdditiveAffineShare::scale_pub_group(base, &scalar.sh);
        let mac = AdditiveAffineShare::scale_pub_group(base, &scalar.mac);
        Self { sh, mac }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.sh.shift(other);
        }
        self.mac.val = Into::<G>::into(Into::<<G as AffineCurve>::Projective>::into(self.mac.val) + (*other * mac_share::<G::ScalarField>()));
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let shares: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let macs: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let sh = AdditiveAffineShare::from_add_shared(M::msm(bases, &shares));
        let mac = AdditiveAffineShare::from_add_shared(M::msm(bases, &macs));
        Self { sh, mac }
    }
}

macro_rules! impl_spdz_basics_2_param {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.sh.val)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.sh.val)
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
                Self::from_public(<T as Uniform>::rand(rng))
            }
        }
    };
}

// impl<T: AffineCurve, M> Uniform for SpdzProjectiveShare<T, M> {
//     fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
//         Self::from_add_shared(<T as Uniform>::rand(rng))
//     }
// }
// impl<T: ProjectiveCurve, M> Uniform for SpdzAffineShare<T, M> {
//     fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
//         Self::from_add_shared(<T as Uniform>::rand(rng))
//     }
// }

impl_spdz_basics_2_param!(SpdzProjectiveShare, ProjectiveCurve);
impl_spdz_basics_2_param!(SpdzAffineShare, AffineCurve);

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct SpdzMulFieldShare<T, S> {
    sh: MulFieldShare<T>,
    mac: MulFieldShare<T>,
    _phants: PhantomData<S>,
}
macro_rules! impl_spdz_basics_2_param_field {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.sh.val)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.sh.val)
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
            fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
                todo!()
                //Self::from_add_shared(<T as Uniform>::rand(rng))
            }
        }
    };
}
impl_spdz_basics_2_param_field!(SpdzMulFieldShare, Field);

impl<F: Field, S: PrimeField> Reveal for SpdzMulFieldShare<F, S> {
    type Base = F;

    fn reveal(self) -> F {
        let vals: Vec<F> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = vals.iter().product();
        let dx_t: F = x.pow(&mac_share::<S>().to_bigint()) / self.mac.val;
        let all_dx_ts: Vec<F> = Net::atomic_broadcast(&dx_t);
        let prod: F = all_dx_ts.iter().product();
        assert!(prod.is_one());
        x
    }
    fn from_public(f: F) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared(f.pow(&mac_share::<S>().to_bigint())),
            _phants: PhantomData::default(),
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared(f.pow(&mac::<S>().to_bigint())),
            _phants: PhantomData::default(),
        }
    }
}

impl<F: Field, S: PrimeField> FieldShare<F> for SpdzMulFieldShare<F, S> {
    fn raw_share(&self) -> F {
        self.sh.val
    }

    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for SpdzMulFieldShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        println!("SpdzMulFieldShare::scale");
        if Net::am_king() {
            self.sh.scale(other);
        }
        self.mac.scale(&other.pow(&mac_share::<S>().to_bigint()));
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for SpdzMulFieldShare")
    }

    fn mul<S2: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S2) -> Self {
        self.sh.mul(other.sh, &mut PanicBeaverSource::default());
        self.mac.mul(other.mac, &mut PanicBeaverSource::default());
        self
    }

    fn batch_mul<S2: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S2,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.sh.mul(y.sh, &mut PanicBeaverSource::default());
            x.mac.mul(y.mac, &mut PanicBeaverSource::default());
        }
        xs
    }

    fn inv<S2: BeaverSource<Self, Self, Self>>(self, _source: &mut S2) -> Self {
        Self {
            sh: self.sh.inv(&mut PanicBeaverSource::default()),
            mac: self.mac.inv(&mut PanicBeaverSource::default()),
            _phants: PhantomData::default(),
        }
    }

    fn batch_inv<S2: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S2) -> Vec<Self> {
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
pub struct SpdzMulExtFieldShare<F: Field, S>(pub PhantomData<(F, S)>);

impl<F: Field, S: PrimeField> ExtFieldShare<F> for SpdzMulExtFieldShare<F, S> {
    type Ext = SpdzMulFieldShare<F, S>;
    type Base = SpdzMulFieldShare<F::BasePrimeField, S>;
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
pub struct SpdzExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for SpdzExtFieldShare<F> {
    type Ext = AdditiveFieldShare<F>;
    type Base = AdditiveFieldShare<F::BasePrimeField>;
}

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = SpdzFieldShare<E::Fr>;
            type AffineShare = SpdzAffineShare<E::$affine, AffineMsm<E::$affine>>;
            type ProjectiveShare = SpdzProjectiveShare<E::$proj, ProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                SpdzProjectiveShare {
                    sh: g.sh.map_homo(|s| s.into()),
                    mac: g.mac.map_homo(|s| s.into()),
                }
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                SpdzAffineShare {
                    sh: g.sh.map_homo(|s| s.into()),
                    mac: g.mac.map_homo(|s| s.into()),
                }
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.sh.val.add_assign_mixed(&o.sh.val);
                a.mac.val.add_assign_mixed(&o.mac.val);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                if Net::am_king() {
                    a.sh.val.add_assign_mixed(&o);
                }
                a.mac.val += (Into::<<E::$affine as AffineCurve>::Projective>::into(*o) * mac_share::<E::Fr>());
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(SpdzG1Share, G1Affine, G1Projective);
groups_share!(SpdzG2Share, G2Affine, G2Projective);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(
        bound = "E::G1Affine: PartialEq<E::G1Projective>, E::G1Projective: PartialEq<E::G1Affine>"
    ),
    Eq(
        bound = "E::G1Affine: Eq, E::G1Projective: Eq"
    ),
    Hash(
        bound = "E::G1Affine: Hash, E::G1Projective: Hash"
    )
)]
pub struct SpdzPairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for SpdzPairingShare<E> {
    type FrShare = SpdzFieldShare<E::Fr>;
    type FqShare = SpdzFieldShare<E::Fq>;
    type FqeShare = SpdzExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = SpdzMulExtFieldShare<E::Fqk, E::Fr>;
    type G1AffineShare = SpdzAffineShare<E::G1Affine, AffineMsm<E::G1Affine>>;
    type G2AffineShare = SpdzAffineShare<E::G2Affine, AffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        SpdzProjectiveShare<E::G1Projective, ProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        SpdzProjectiveShare<E::G2Projective, ProjectiveMsm<E::G2Projective>>;
    type G1 = SpdzG1Share<E>;
    type G2 = SpdzG2Share<E>;
}
