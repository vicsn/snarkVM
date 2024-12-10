use derivative::Derivative;
use log::debug;
use rand::Rng;
use zeroize::Zeroize;

use snarkvm_curves::{ProjectiveCurve, AffineCurve};
// use ark_ff::bytes::{FromBytes, ToBytes};
// use ark_ff::prelude::*;
use snarkvm_utilities::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError, FromBytes, ToBytes, Uniform, Compress, Validate, Valid,
};
use snarkvm_fields::{Zero, One};
use snarkvm_curves::MpcWire;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::*;

use crate::{
    {ProjectiveGroupShare, AffineGroupShare},
    BeaverSource,
    Reveal,
};

use crate::MpcField;

use mpc_net::{MpcNet, MpcMultiNet as Net};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq)]
pub enum MpcProjectiveGroup<G: ProjectiveCurve, S: ProjectiveGroupShare<G>> {
    Public(G),
    Shared(S),
}

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq)]
pub enum MpcAffineGroup<G: AffineCurve, S: AffineGroupShare<G>> {
    Public(G),
    Shared(S),
}

impl_basics_group!(ProjectiveGroupShare, ProjectiveCurve, MpcProjectiveGroup, MpcAffineGroup, AffineGroupShare, AffineCurve);
impl_basics_group!(AffineGroupShare, AffineCurve, MpcAffineGroup, MpcProjectiveGroup, ProjectiveGroupShare, ProjectiveCurve);

impl<'a, T: ProjectiveCurve, S: ProjectiveGroupShare<T>> AddAssign<&'a MpcProjectiveGroup<T, S>> for MpcProjectiveGroup<T, S> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcProjectiveGroup::Public(x) => match other {
                MpcProjectiveGroup::Public(y) => {
                    *x += *y;
                }
                MpcProjectiveGroup::Shared(y) => {
                    let mut tt = *y;
                    tt.shift(x);
                    *self = MpcProjectiveGroup::Shared(tt);
                }
            },
            MpcProjectiveGroup::Shared(x) => match other {
                MpcProjectiveGroup::Public(y) => {
                    x.shift(y);
                }
                MpcProjectiveGroup::Shared(y) => {
                    x.add(y);
                }
            },
        }
    }
}
impl<T: ProjectiveCurve, S: ProjectiveGroupShare<T>> Sum for MpcProjectiveGroup<T, S> {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}
impl<'a, T: ProjectiveCurve, S: ProjectiveGroupShare<T> + 'a> Sum<&'a MpcProjectiveGroup<T, S>> for MpcProjectiveGroup<T, S> {
    #[inline]
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |x, y| x.add(y.clone()))
    }
}
impl<'a, T: ProjectiveCurve, S: ProjectiveGroupShare<T>> SubAssign<&'a MpcProjectiveGroup<T, S>> for MpcProjectiveGroup<T, S> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcProjectiveGroup::Public(x) => match other {
                MpcProjectiveGroup::Public(y) => {
                    *x -= y;
                }
                MpcProjectiveGroup::Shared(y) => {
                    let mut t = *y;
                    t.neg().shift(&x);
                    *self = MpcProjectiveGroup::Shared(t);
                }
            },
            MpcProjectiveGroup::Shared(x) => match other {
                MpcProjectiveGroup::Public(y) => {
                    x.shift(&-*y);
                }
                MpcProjectiveGroup::Shared(y) => {
                    x.sub(y);
                }
            },
        }
    }
}


#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSourceProjective<T: ProjectiveCurve, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSourceAffine<T: AffineCurve, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

macro_rules! beaver_source_group_share {
    ($base_bound:ident, $group_share:ident, $target:ident) => {
        impl<T: $base_bound, S: $group_share<T>> BeaverSource<S, S::FieldShare, S>
            for $target<T, S>
        {
            #[inline]
            fn triple(&mut self) -> (S, S::FieldShare, S) {
                (
                    S::from_add_shared(T::zero()),
                    <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                        T::ScalarField::one()
                    } else {
                        T::ScalarField::zero()
                    }),
                    S::from_add_shared(T::zero()),
                )
            }
            #[inline]
            fn inv_pair(&mut self) -> (S::FieldShare, S::FieldShare) {
                (
                    <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                        T::ScalarField::one()
                    } else {
                        T::ScalarField::zero()
                    }),
                    <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                        T::ScalarField::one()
                    } else {
                        T::ScalarField::zero()
                    }),
                )
            }
        }
    };
}

beaver_source_group_share!(ProjectiveCurve, ProjectiveGroupShare, DummyGroupTripleSourceProjective);
beaver_source_group_share!(AffineCurve, AffineGroupShare, DummyGroupTripleSourceAffine);

impl_ref_ops_group!(Add, AddAssign, add, add_assign, ProjectiveCurve,ProjectiveGroupShare, MpcProjectiveGroup);
impl_ref_ops_group!(Add, AddAssign, add, add_assign, AffineCurve,AffineGroupShare, MpcAffineGroup);
impl_ref_ops_group!(Sub, SubAssign, sub, sub_assign, ProjectiveCurve,ProjectiveGroupShare, MpcProjectiveGroup);
impl_ref_ops_group!(Sub, SubAssign, sub, sub_assign, AffineCurve,AffineGroupShare, MpcAffineGroup);

macro_rules! impl_mpc_group {
    ($base_bound:ident, $group_share:ident, $mpc_group:ident, $triple:ident) => {
        impl<T: $base_bound, S: $group_share<T>> MpcWire for $mpc_group<T, S> {
            #[inline]
            fn publicize(&mut self) {
                match self {
                    $mpc_group::Shared(s) => {
                        *self = $mpc_group::Public(s.reveal());
                    }
                    _ => {}
                }
                debug_assert!({
                    let self_val = if let $mpc_group::Public(s) = self {
                        s.clone()
                    } else {
                        unreachable!()
                    };
                    super::macros::check_eq(self_val);
                    true
                })
            }
            #[inline]
            fn is_shared(&self) -> bool {
                match self {
                    $mpc_group::Shared(_) => true,
                    $mpc_group::Public(_) => false,
                }
            }
        }
        
        impl<T: $base_bound, S: $group_share<T>> Reveal for $mpc_group<T, S> {
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
                Self::Public(b)
            }
            #[inline]
            fn from_add_shared(b: Self::Base) -> Self {
                Self::Shared(S::from_add_shared(b))
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
        
        
        // impl<T: Group, S: $group_share<T>> Group for $mpc_group<T, S> {
        // }
        impl<T: $base_bound, S: $group_share<T>> $mpc_group<T, S> {
            pub fn unwrap_as_public_or_add_shared(self) -> T {
                match self {
                    Self::Public(p) => p,
                    Self::Shared(p) => p.unwrap_as_public(),
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
                } else if out_b.len() > 0 {
                    Err(out_b)
                } else {
                    Ok(out_a)
                }
            }
        }
    };
}

impl_mpc_group!(ProjectiveCurve, ProjectiveGroupShare, MpcProjectiveGroup, DummyGroupTripleSourceProjective);
impl_mpc_group!(AffineCurve, AffineGroupShare, MpcAffineGroup, DummyGroupTripleSourceAffine);

impl<T: ProjectiveCurve, S: ProjectiveGroupShare<T>> Mul<MpcField<T::ScalarField, S::FieldShare>> for MpcProjectiveGroup<T, S> {
    type Output = Self;
    #[inline]
    fn mul(mut self, other: MpcField<T::ScalarField, S::FieldShare>) -> Self::Output {
        self *= &other;
        self
    }
}

impl<'a, T: ProjectiveCurve, S: ProjectiveGroupShare<T>> Mul<&'a MpcField<T::ScalarField, S::FieldShare>>
    for MpcProjectiveGroup<T, S>
{
    type Output = Self;
    #[inline]
    fn mul(mut self, other: &MpcField<T::ScalarField, S::FieldShare>) -> Self::Output {
        self *= other;
        self
    }
}
impl<T: ProjectiveCurve, S: ProjectiveGroupShare<T>> MulAssign<MpcField<T::ScalarField, S::FieldShare>>
    for MpcProjectiveGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: MpcField<T::ScalarField, S::FieldShare>) {
        *self *= &other;
    }
}
impl<'a, T: ProjectiveCurve, S: ProjectiveGroupShare<T>> MulAssign<&'a MpcField<T::ScalarField, S::FieldShare>>
    for MpcProjectiveGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: &MpcField<T::ScalarField, S::FieldShare>) { // TODO: many traits only exist for Projective
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcProjectiveGroup::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= *y;
                }
                MpcField::Shared(y) => {
                    let t = MpcProjectiveGroup::Shared(S::scale_pub_group(*x, &y));
                    *self = t;
                }
            },
            MpcProjectiveGroup::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale_pub_scalar(y);
                }
                MpcField::Shared(y) => {
                    let t = x.scale(*y, &mut DummyGroupTripleSourceProjective::default());
                    *x = t;
                }
            },
        }
    }
}
