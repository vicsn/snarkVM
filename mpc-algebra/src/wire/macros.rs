#![macro_use]

use snarkvm_fields::{Zero, MpcWire};
use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize};

use crate::channel::{self, MpcSerNet};
use mpc_net::MpcNet;

use std::fmt::{Display, Debug};

#[track_caller]
/// Checks that both sides of the channel have the same value.
pub fn check_eq<T: CanonicalSerialize + CanonicalDeserialize + Clone + Eq + Display>(t: T) {
    // println!("check_eq for type {}", std::any::type_name::<T>());
    debug_assert!({
        use log::debug;
        if mpc_net::two::is_init() {
            let other = channel::exchange(&t);
            if t == other {
                debug!("Consistency check passed");
                true
            } else {
                println!("\nConsistency check failed\n{}\nvs\n{} \n\n", t, other); //, std::backtrace::Backtrace::force_capture());
                false
            }
        } else {
            debug!("Consistency check");
            let others = mpc_net::MpcMultiNet::broadcast(&t);
            let mut result = true;
            for (i, other_t) in others.iter().enumerate() {
                if &t != other_t {
                    println!("\nConsistency check failed\nI (party {}) have {}\nvs\n  (party {}) has {} \n\n - backtrace: {}", mpc_net::MpcMultiNet::party_id(), t, i, other_t, std::backtrace::Backtrace::force_capture());
                    result = false;
                    break;
                }
            }
            // true
            result
        }
    })
}

#[track_caller]
/// Publicize vector while ensuring the length is equal.
pub fn publicize_vector<T: MpcWire + Zero + CanonicalSerialize + CanonicalDeserialize + Clone + Eq + Display + Debug>(t: &mut Vec<T>) {
    // println!("publicize_vector for vector of type {}", std::any::type_name::<T>());
    if mpc_net::two::is_init() {
        let other = channel::exchange(&t.len());
        let length_diff = other.saturating_sub(t.len());
        for _ in 0..length_diff {
            t.push(T::zero());
        }
        println!("t: {:?}", t);
        t.publicize();
    } else {
        let others = mpc_net::MpcMultiNet::broadcast(&t.len());
        for other in others {
            let length_diff = other.saturating_sub(t.len());
            for _ in 0..length_diff {
                t.push(T::zero());
            }
            println!("t: {:?}", t);
            t.publicize();
        }
    }
}

macro_rules! impl_basics_group {
    ($share:ident, $bound:ident, $wrap:ident, $mapped:ident, $mapped_share:ident, $mapped_bound:ident) => {
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            #[inline]
            pub fn new(t: T, shared: bool) -> Self {
                if shared {
                    Self::Shared(<S as Reveal>::from_public(t))
                } else {
                    Self::Public(t)
                }
            }
            #[inline]
            pub fn from_public(t: T) -> Self {
                Self::new(t, false)
            }
            #[inline]
            pub fn map<TT: $mapped_bound, SS: $mapped_share<TT>, FT: Fn(T) -> TT, FS: Fn(S) -> SS>(
                self,
                ft: FT,
                fs: FS,
            ) -> $mapped<TT, SS> {
                match self {
                    Self::Shared(s) => $mapped::Shared(fs(s)),
                    Self::Public(s) => $mapped::Public(ft(s)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Display for $wrap<T, S> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    $wrap::Public(x) => write!(f, "{} (public)", x),
                    $wrap::Shared(x) => write!(f, "{} (shared)", x),
                }
            }
        }
        impl<T: $bound, S: $share<T>> ToBytes for $wrap<T, S> {
            fn write_le<W: Write>(&self, writer: W) -> io::Result<()> {
                match self {
                    Self::Public(v) => v.write_le(writer),
                    Self::Shared(_) => unimplemented!("write share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> FromBytes for $wrap<T, S> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, S: $share<T>> Valid for $wrap<T, S> {
            fn check(&self) -> Result<(), SerializationError> {
                match self {
                    Self::Public(v) => v.check(),
                    Self::Shared(_) => unimplemented!("check share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerialize for $wrap<T, S> {
            fn serialize_with_mode<W: Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
                match self {
                    Self::Public(v) => v.serialize_with_mode(writer, compress),
                    Self::Shared(_) => unimplemented!("serialize share: {}", self),
                }
            }
            fn serialized_size(&self, compress: Compress) -> usize {
                match self {
                    Self::Public(v) => v.serialized_size(compress),
                    Self::Shared(_) => unimplemented!("serialized_size share: {}", self),
                }
            }
        }
        // NB: CanonicalSerializeWithFlags is unimplemented for Group.
        impl<T: $bound, S: $share<T>> CanonicalSerializeWithFlags for $wrap<T, S> {
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
        impl<T: $bound, S: $share<T>> CanonicalDeserialize for $wrap<T, S> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserializeWithFlags for $wrap<T, S> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> Uniform for $wrap<T, S> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as Uniform>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn rand_shared<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as Uniform>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn rand_public<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Public(<T as Uniform>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> Neg for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self::Output {
                match self {
                    $wrap::Public(x) => $wrap::Public(-x),
                    $wrap::Shared(mut x) => $wrap::Shared({
                        x.neg();
                        x
                    }),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zero for $wrap<T, S> {
            #[inline]
            fn zero() -> Self {
                $wrap::Public(T::zero())
            }
            #[inline]
            fn is_zero(&self) -> bool {
                match self {
                    $wrap::Public(x) => x.is_zero(),
                    $wrap::Shared(_x) => {
                        debug!("Warning: is_zero on shared data. Returning false");
                        false
                    }
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zeroize for $wrap<T, S> {
            #[inline]
            fn zeroize(&mut self) {
                *self = $wrap::Public(T::zero());
            }
        }
        impl<T: $bound, S: $share<T>> Default for $wrap<T, S> {
            fn default() -> Self {
                Self::zero()
            }
        }
    };
}

macro_rules! impl_basics_field {
    ($share:ident, $bound:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            #[inline]
            pub fn new(t: T, shared: bool) -> Self {
                if shared {
                    Self::Shared(<S as Reveal>::from_public(t))
                } else {
                    Self::Public(t)
                }
            }
            #[inline]
            pub fn from_public(t: T) -> Self {
                Self::new(t, false)
            }
            #[inline]
            pub fn map<TT: $bound, SS: $share<TT>, FT: Fn(T) -> TT, FS: Fn(S) -> SS>(
                self,
                ft: FT,
                fs: FS,
            ) -> $wrap<TT, SS> {
                match self {
                    Self::Shared(s) => $wrap::Shared(fs(s)),
                    Self::Public(s) => $wrap::Public(ft(s)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Display for $wrap<T, S> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    $wrap::Public(x) => write!(f, "{} (public)", x),
                    $wrap::Shared(x) => write!(f, "{} (shared)", x),
                }
            }
        }
        impl<T: $bound, S: $share<T>> ToBytes for $wrap<T, S> {
            fn write_le<W: Write>(&self, writer: W) -> io::Result<()> {
                match self {
                    Self::Public(v) => v.write_le(writer),
                    Self::Shared(_) => unimplemented!("write share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> FromBytes for $wrap<T, S> {
            fn read_le<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, S: $share<T>> Valid for $wrap<T, S> {
            fn check(&self) -> Result<(), SerializationError> {
                match self {
                    Self::Public(v) => v.check(),
                    Self::Shared(_) => unimplemented!("check share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerialize for $wrap<T, S> {
            fn serialize_with_mode<W: Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
                match self {
                    Self::Public(v) => v.serialize_with_mode(writer, compress),
                    Self::Shared(_) => unimplemented!("serialize share: {}", self),
                }
            }
            fn serialized_size(&self, compress: Compress) -> usize {
                match self {
                    Self::Public(v) => v.serialized_size(compress),
                    Self::Shared(_) => unimplemented!("serialized_size share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerializeWithFlags for $wrap<T, S> {
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
        impl<T: $bound, S: $share<T>> CanonicalDeserialize for $wrap<T, S> {
            fn deserialize_with_mode<R: Read>(
                _reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                unimplemented!("deserialize_with_mode")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserializeWithFlags for $wrap<T, S> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> Uniform for $wrap<T, S> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as Uniform>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn rand_shared<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as Uniform>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn rand_public<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Public(<T as Uniform>::rand(rng))
            }
        }
        impl<'a, T: $bound, S: $share<T>> AddAssign<&'a $wrap<T, S>> for $wrap<T, S> {
            #[inline]
            fn add_assign(&mut self, other: &Self) {
                match self {
                    // for some reason, a two-stage match (rather than a tuple match) avoids moving
                    // self
                    $wrap::Public(x) => match other {
                        $wrap::Public(y) => {
                            *x += *y;
                        }
                        $wrap::Shared(y) => {
                            let mut tt = *y;
                            tt.shift(x);
                            *self = $wrap::Shared(tt);
                        }
                    },
                    $wrap::Shared(x) => match other {
                        $wrap::Public(y) => {
                            x.shift(y);
                        }
                        $wrap::Shared(y) => {
                            x.add(y);
                        }
                    },
                }
            }
        }
        impl<T: $bound, S: $share<T>> Sum for $wrap<T, S> {
            #[inline]
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), Add::add)
            }
        }
        impl<'a, T: $bound, S: $share<T> + 'a> Sum<&'a $wrap<T, S>> for $wrap<T, S> {
            #[inline]
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), |x, y| x.add(y.clone()))
            }
        }
        impl<T: $bound, S: $share<T>> Neg for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self::Output {
                match self {
                    $wrap::Public(x) => $wrap::Public(-x),
                    $wrap::Shared(mut x) => $wrap::Shared({
                        x.neg();
                        x
                    }),
                }
            }
        }
        impl<'a, T: $bound, S: $share<T>> SubAssign<&'a $wrap<T, S>> for $wrap<T, S> {
            #[inline]
            fn sub_assign(&mut self, other: &Self) {
                match self {
                    // for some reason, a two-stage match (rather than a tuple match) avoids moving
                    // self
                    $wrap::Public(x) => match other {
                        $wrap::Public(y) => {
                            *x -= y;
                        }
                        $wrap::Shared(y) => {
                            let mut t = *y;
                            t.neg().shift(&x);
                            *self = $wrap::Shared(t);
                        }
                    },
                    $wrap::Shared(x) => match other {
                        $wrap::Public(y) => {
                            x.shift(&-*y);
                        }
                        $wrap::Shared(y) => {
                            x.sub(y);
                        }
                    },
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zero for $wrap<T, S> {
            #[inline]
            fn zero() -> Self {
                $wrap::Public(T::zero())
                // $wrap::Shared(<S as Reveal>::from_public(T::zero()))
            }
            #[inline]
            fn is_zero(&self) -> bool {
                match self {
                    $wrap::Public(x) => x.is_zero(),
                    $wrap::Shared(_x) => {
                        debug!("Warning: is_zero on shared data. Returning false");
                        false
                    }
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zeroize for $wrap<T, S> {
            #[inline]
            fn zeroize(&mut self) {
                *self = $wrap::Public(T::zero());
            }
        }
        impl<T: $bound, S: $share<T>> Default for $wrap<T, S> {
            fn default() -> Self {
                Self::zero()
            }
        }
    };
}

macro_rules! impl_ref_ops_group {
    ($op:ident, $assop:ident, $opfn:ident, $assopfn:ident, $bound:ident, $share:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> $op<$wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn $opfn(mut self, other: $wrap<T, S>) -> Self::Output {
                self.$assopfn(other);
                self
            }
        }
        impl<'a, T: $bound, S: $share<T>> $op<&'a $wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn $opfn(mut self, other: &$wrap<T, S>) -> Self::Output {
                self.$assopfn(*other);
                self
            }
        }
        impl<T: $bound, S: $share<T>> $assop<$wrap<T, S>> for $wrap<T, S> {
            #[inline]
            fn $assopfn(&mut self, other: $wrap<T, S>) {
                self.$assopfn(other);
            }
        }
        // impl<'a, T: $bound, S: $share<T>> $assop<&'a $wrap<T, S>> for $wrap<T, S> {
        //     #[inline]
        //     fn $assopfn(&mut self, other: &$wrap<T, S>) {
        //         *self = self.clone().$opfn(other.clone());
        //     }
        // }
    };
}

macro_rules! impl_ref_ops {
    ($op:ident, $assop:ident, $opfn:ident, $assopfn:ident, $bound:ident, $share:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> $op<$wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn $opfn(mut self, other: $wrap<T, S>) -> Self::Output {
                self.$assopfn(&other);
                self
            }
        }
        impl<'a, T: $bound, S: $share<T>> $op<&'a $wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            #[inline]
            fn $opfn(mut self, other: &$wrap<T, S>) -> Self::Output {
                self.$assopfn(other);
                self
            }
        }
        impl<T: $bound, S: $share<T>> $assop<$wrap<T, S>> for $wrap<T, S> {
            #[inline]
            fn $assopfn(&mut self, other: $wrap<T, S>) {
                self.$assopfn(&other);
            }
        }
        // impl<'a, T: $bound, S: $share<T>> $assop<&'a $wrap<T, S>> for $wrap<T, S> {
        //     #[inline]
        //     fn $assopfn(&mut self, other: &$wrap<T, S>) {
        //         *self = self.clone().$opfn(other.clone());
        //     }
        // }
    };
}

macro_rules! from_prim {
    ($t:ty, $bound:ident, $share:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> std::convert::From<$t> for $wrap<T, S> {
            #[inline]
            fn from(t: $t) -> Self {
                $wrap::from_public(T::from(t))
            }
        }
    };
}
