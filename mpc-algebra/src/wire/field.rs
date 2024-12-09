use derivative::Derivative;
use log::debug;
use rand::Rng;
use zeroize::Zeroize;

use snarkvm_fields::{FftField, Field, One, PoseidonDefaultField, PoseidonParameters, PrimeField, SquareRootField, Zero};
use snarkvm_utilities::{
    BigInteger, CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, Compress, Flags, FromBytes, SerializationError, ToBytes, Uniform, Valid, Validate
};
use snarkvm_curves::MpcWire;
use crate::{FieldShare, BeaverSource, Reveal};
use crate::MpcBigInteger;
use crate::MpcFrParameters;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::*;

use anyhow;

use mpc_net::{MpcNet, MpcMultiNet as Net};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

impl_basics_field!(FieldShare, Field, MpcField);

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyFieldTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: FieldShare<T>> BeaverSource<S, S, S> for DummyFieldTripleSource<T, S> {
    #[inline]
    fn triple(&mut self) -> (S, S, S) {
        (
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S, S) {
        (
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
        )
    }
}

impl<T: Field, S: FieldShare<T>> MpcField<T, S> {
    #[inline]
    pub fn inv(self) -> Option<Self> {
        match self {
            Self::Public(x) => x.inverse().map(MpcField::Public),
            Self::Shared(x) => Some(MpcField::Shared(
                x.inv(&mut DummyFieldTripleSource::default()),
            )),
        }
    }
    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<T>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => out_a.push(x),
                Self::Shared(x) => out_b.push(x),
            }
        }
        if out_a.len() > 0 && out_b.len() > 0 {
            panic!("Heterogeous")
        } else if out_a.len() > 0 {
            Ok(out_a)
        } else {
            Err(out_b)
        }
    }
}
impl<'a, T: Field, S: FieldShare<T>> MulAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= y;
                }
                MpcField::Shared(y) => {
                    let mut t = *y;
                    t.scale(x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(y);
                }
                MpcField::Shared(y) => {
                    let t = x.mul(*y, &mut DummyFieldTripleSource::default());
                    *self = MpcField::Shared(t);
                }
            },
        }
    }
}
impl<T: Field, S: FieldShare<T>> One for MpcField<T, S> {
    #[inline]
    fn one() -> Self {
        MpcField::Public(T::one())
    }
}
impl<T: Field, S: FieldShare<T>> Product for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}
impl<'a, T: Field, S: FieldShare<T> + 'a> Product<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |x, y| x.mul(y.clone()))
    }
}

impl<'a, T: Field, S: FieldShare<T>> DivAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x /= y;
                }
                MpcField::Shared(y) => {
                    let mut t = y.inv(&mut DummyFieldTripleSource::default());
                    t.scale(&x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(&y.inverse().unwrap());
                }
                MpcField::Shared(y) => {
                    let src = &mut DummyFieldTripleSource::default();
                    *x = x.div(*y, src);
                }
            },
        }
    }
}

impl_ref_ops!(
    Mul,
    MulAssign,
    mul,
    mul_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Add,
    AddAssign,
    add,
    add_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Div,
    DivAssign,
    div,
    div_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Sub,
    SubAssign,
    sub,
    sub_assign,
    Field,
    FieldShare,
    MpcField
);

impl<T: Field, S: FieldShare<T>> MpcWire for MpcField<T, S> {
    #[inline]
    fn publicize(&mut self) {
        match self {
            MpcField::Shared(s) => {
                *self = MpcField::Public(s.open());
            }
            _ => {}
        }
        debug_assert!({
            let self_val = if let MpcField::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val.clone());
            true
        })
    }
    #[inline]
    fn is_shared(&self) -> bool {
        match self {
            MpcField::Shared(_) => true,
            MpcField::Public(_) => false,
        }
    }
}

impl<T: Field, S: FieldShare<T>> Reveal for MpcField<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result.clone());
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        MpcField::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        Self::Shared(S::king_share(f, rng))
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        S::king_share_batch(f, rng).into_iter().map(Self::Shared).collect()
    }
    fn init_protocol() {
        S::init_protocol()
    }
    fn deinit_protocol() {
        S::deinit_protocol()
    }
}

// from_prim!(bool, Field, FieldShare, MpcField);
from_prim!(u8, Field, FieldShare, MpcField);
from_prim!(u16, Field, FieldShare, MpcField);
from_prim!(u32, Field, FieldShare, MpcField);
from_prim!(u64, Field, FieldShare, MpcField);
from_prim!(u128, Field, FieldShare, MpcField);

impl<T: PrimeField, S: FieldShare<T>> std::str::FromStr for MpcField<T, S> {
    type Err = T::Err;
    #[inline]
    fn from_str(s: &str) -> Result<Self, T::Err> {
        T::from_str(s).map(Self::Public)
    }
}

// NOTE: there is already a default implementation for fn poseidon_params...
impl<F: PrimeField, S: FieldShare<F>> PoseidonDefaultField for MpcField<F, S> {
    fn default_poseidon_parameters<const RATE: usize>() -> anyhow::Result<PoseidonParameters<Self, RATE, 1>>
    where
        Self: PrimeField,
    {
        let PoseidonParameters::<F, RATE, 1> {
            full_rounds,
            partial_rounds,
            alpha,
            ark,
            mds,
        } = F::default_poseidon_parameters::<RATE>().unwrap();

        Ok(PoseidonParameters::<Self, RATE, 1> {
            full_rounds,
            partial_rounds,
            alpha,
            ark: Reveal::from_public(ark), //ark.into_iter().map(|a| MpcField::<F, S>::from_public(a)).collect(),
            mds: Reveal::from_public(mds), //.into_iter().map(|m| m.into_iter().map(|m| MpcField::<F, S>::from_public(m)).collect()).collect(),
        })
    }
}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;
    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        F::characteristic()
    }
    // #[inline]
    // fn extension_degree() -> u64 {
    //     unimplemented!("extension_degree")
    // }
    #[inline]
    fn from_base_prime_field(_b: <Self as snarkvm_fields::Field>::BasePrimeField) -> Self {
        unimplemented!()
        // assert!(b.len() > 0);
        // let shared = b[0].is_shared();
        // assert!(b.iter().all(|e| e.is_shared() == shared));
        // let base_values = b.iter().map(|e| e.unwrap_as_public()).collect::<Vec<_>>();
        // F::from_base_prime_field_elems(&base_values).map(|val| Self::new(val, shared))
    }
    #[inline]
    fn double(&self) -> Self {
        Self::Public(F::from(2u8)) * self
    }
    #[inline]
    fn double_in_place(&mut self) {
        *self *= Self::Public(F::from(2u8));
    }
    #[inline]
    fn from_random_bytes_with_flags<Fl: Flags>(b: &[u8]) -> Option<(Self, Fl)> {
        F::from_random_bytes_with_flags(b).map(|(val, f)| (Self::Shared(S::from_public(val)), f))
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
        self.inv()
    }
    #[inline]
    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.inv().map(|i| {
            *self = i;
            self
        })
    }
    #[inline]
    fn frobenius_map(&mut self, _: usize) {
        unimplemented!("frobenius_map")
    }

    // fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
    //     let selfs_shared = selfs[0].is_shared();
    //     let others_shared = others[0].is_shared();
    //     assert!(
    //         selfs.iter().all(|s| s.is_shared() == selfs_shared),
    //         "Selfs heterogenously shared!"
    //     );
    //     assert!(
    //         others.iter().all(|s| s.is_shared() == others_shared),
    //         "others heterogenously shared!"
    //     );
    //     if selfs_shared && others_shared {
    //         let sshares = selfs
    //             .iter()
    //             .map(|s| match s {
    //                 Self::Shared(s) => s.clone(),
    //                 Self::Public(_) => unreachable!(),
    //             })
    //             .collect();
    //         let oshares = others
    //             .iter()
    //             .map(|s| match s {
    //                 Self::Shared(s) => s.clone(),
    //                 Self::Public(_) => unreachable!(),
    //             })
    //             .collect();
    //         let nshares = S::batch_mul(sshares, oshares, &mut DummyFieldTripleSource::default());
    //         for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
    //             *self_ = Self::Shared(new);
    //         }
    //     } else {
    //         for (a, b) in snarkvm_utilities::cfg_iter_mut!(selfs).zip(others.iter()) {
    //             *a *= b;
    //         }
    //     }
    // }
    // fn batch_division_in_place(selfs: &mut [Self], others: &[Self]) {
    //     let selfs_shared = selfs[0].is_shared();
    //     let others_shared = others[0].is_shared();
    //     assert!(
    //         selfs.iter().all(|s| s.is_shared() == selfs_shared),
    //         "Selfs heterogenously shared!"
    //     );
    //     assert!(
    //         others.iter().all(|s| s.is_shared() == others_shared),
    //         "others heterogenously shared!"
    //     );
    //     if selfs_shared && others_shared {
    //         let sshares = selfs
    //             .iter()
    //             .map(|s| match s {
    //                 Self::Shared(s) => s.clone(),
    //                 Self::Public(_) => unreachable!(),
    //             })
    //             .collect();
    //         let oshares = others
    //             .iter()
    //             .map(|s| match s {
    //                 Self::Shared(s) => s.clone(),
    //                 Self::Public(_) => unreachable!(),
    //             })
    //             .collect();
    //         let nshares = S::batch_div(sshares, oshares, &mut DummyFieldTripleSource::default());
    //         for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
    //             *self_ = Self::Shared(new);
    //         }
    //     } else {
    //         for (a, b) in snarkvm_utilities::cfg_iter_mut!(selfs).zip(others.iter()) {
    //             *a *= b;
    //         }
    //     }
    // }
    // fn partial_products_in_place(selfs: &mut [Self]) {
    //     let selfs_shared = selfs[0].is_shared();
    //     assert!(
    //         selfs.iter().all(|s| s.is_shared() == selfs_shared),
    //         "Selfs heterogenously shared!"
    //     );
    //     if selfs_shared {
    //         let sshares = selfs
    //             .iter()
    //             .map(|s| match s {
    //                 Self::Shared(s) => s.clone(),
    //                 Self::Public(_) => unreachable!(),
    //             })
    //             .collect();
    //         for (self_, new) in selfs.iter_mut().zip(
    //             S::partial_products(sshares, &mut DummyFieldTripleSource::default()).into_iter(),
    //         ) {
    //             *self_ = Self::Shared(new);
    //         }
    //     } else {
    //         for i in 1..selfs.len() {
    //             let last = selfs[i - 1];
    //             selfs[i] *= &last;
    //         }
    //     }
    // }
    // fn has_univariate_div_qr() -> bool {
    //     true
    // }
    // fn univariate_div_qr<'a>(
    //     num: snarkvm_fft::fft::Polynomial<Self>,
    //     den: snarkvm_fft::fft::Polynomial<Self>,
    // ) -> Option<(
    //     poly_stub::DensePolynomial<Self>,
    //     poly_stub::DensePolynomial<Self>,
    // )> {
    //     use snarkvm_fft::fft::Polynomial::*;
    //     let shared_num = match num {
    //         DPolynomial(d) => Ok(d.into_owned().coeffs.into_iter().map(|c| match c {
    //             MpcField::Shared(s) => s,
    //             MpcField::Public(_) => panic!("public numerator"),
    //         }).collect()),
    //         SPolynomial(d) => Err(d.into_owned().coeffs.into_iter().map(|(i, c)| match c {
    //             MpcField::Shared(s) => (i, s),
    //             MpcField::Public(_) => panic!("public numerator"),
    //         }).collect()),
    //     };
    //     let pub_denom = match den {
    //         DPolynomial(d) => Ok(d.into_owned().coeffs.into_iter().map(|c| match c {
    //             MpcField::Public(s) => s,
    //             MpcField::Shared(_) => panic!("shared denominator"),
    //         }).collect()),
    //         SPolynomial(d) => Err(d.into_owned().coeffs.into_iter().map(|(i, c)| match c {
    //             MpcField::Public(s) => (i, s),
    //             MpcField::Shared(_) => panic!("shared denominator"),
    //         }).collect()),
    //     };
    //     S::univariate_div_qr(shared_num, pub_denom).map(|(q, r)| {
    //         (
    //             poly_stub::DensePolynomial {
    //                 coeffs: q.into_iter().map(|qc| MpcField::Shared(qc)).collect(),
    //             },
    //             poly_stub::DensePolynomial {
    //                 coeffs: r.into_iter().map(|rc| MpcField::Shared(rc)).collect(),
    //             },
    //         )
    //     })
    // }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    type FftParameters = MpcFrParameters<F, S, F::BigInteger>; //F::FftParameters;
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

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type BigInteger = &'static MpcBigInteger<F, S, F::BigInteger>;
    type Parameters = MpcFrParameters<F, S, F::BigInteger>;

    #[inline]
    fn from_bigint(r: <Self as PrimeField>::BigInteger) -> Option<Self> {
        // TODO: from where is this called?
        // TODO: is it semantically correct to always return a public field here?
        Some(MpcField::<F, S>::Public(
            F::from_bigint(r.val.clone()).unwrap()
        ))
    }
    // We're assuming that into_repr is linear
    #[inline]
    fn to_bigint(&self) -> <Self as PrimeField>::BigInteger {
        // TODO: from where is this called?
        // TODO: is it semantically correct to always return a public integer here?
        &'static MpcBigInteger::<F, S, F::BigInteger> {
            val: self.reveal().to_bigint(),
            _marker: PhantomData,
        }
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
        unimplemented!("No BigInt reprs for shared fields! (decompose)")
    }
}

impl<F: PrimeField, S: FieldShare<F>> SquareRootField for MpcField<F, S> {
    #[inline]
    fn legendre(&self) -> snarkvm_fields::LegendreSymbol {
        todo!()
    }
    #[inline]
    fn sqrt(&self) -> Option<Self> {
        todo!()
    }
    #[inline]
    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }
}

mod poly_impl {

    use super::*;
    // use crate::share::*;
    // use crate::wire::*;
    use crate::{Reveal, struct_reveal_simp_impl, FieldShare};
    // use snarkvm_fields::PrimeField;
    use snarkvm_fft::fft::{EvaluationDomain, Evaluations, DensePolynomial};

    impl<E: PrimeField, S: FieldShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
        type Base = DensePolynomial<E>;
        struct_reveal_simp_impl!(DensePolynomial; coeffs);
    }

    impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>> {
        type Base = Evaluations<F>;

        fn reveal(self) -> Self::Base {
            let domain_size = self.domain().size();
            Evaluations::from_vec_and_domain(
                self.evaluations.reveal(),
                EvaluationDomain::new(domain_size).unwrap(),
            )
        }

        fn from_add_shared(b: Self::Base) -> Self {
            let domain_size = b.domain().size();
            Evaluations::from_vec_and_domain(
                Reveal::from_add_shared(b.evaluations),
                EvaluationDomain::new(domain_size).unwrap(),
            )
        }

        fn from_public(b: Self::Base) -> Self {
            let domain_size = b.domain().size();
            Evaluations::from_vec_and_domain(
                Reveal::from_public(b.evaluations),
                EvaluationDomain::new(domain_size).unwrap(),
            )
        }
    }
}
