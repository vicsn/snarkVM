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

#[allow(unused_imports)]
use blst::*;

use core::ffi::c_void;
use snarkvm_curves::bls12_377::{Fr, G1Affine, G1Projective};
use snarkvm_utilities::BigInteger256;
use std::any::TypeId;
sppark::cuda_error!();

#[repr(C)]
pub enum NTTInputOutputOrder {
    NN = 0,
    NR = 1,
    RN = 2,
    RR = 3,
}

#[repr(C)]
pub enum NTTDirection {
    Forward = 0,
    Inverse = 1,
}

#[repr(C)]
pub enum NTTType {
    Standard = 0,
    Coset = 1,
}

extern "C" {
    fn snarkvm_ntt(
        inout: *mut core::ffi::c_void,
        lg_domain_size: u32,
        ntt_order: NTTInputOutputOrder,
        ntt_direction: NTTDirection,
        ntt_type: NTTType,
    ) -> cuda::Error;

    fn snarkvm_polymul(
        out: *mut core::ffi::c_void,
        pcount: usize,
        polynomials: *const core::ffi::c_void,
        plens: *const core::ffi::c_void,
        ecount: usize,
        evaluations: *const core::ffi::c_void,
        elens: *const core::ffi::c_void,
        lg_domain_size: u32,
    ) -> cuda::Error;

    fn snarkvm_blst_platform_cap() -> core::ffi::c_int;

    fn snarkvm_msm(
        out: *mut c_void,
        points_with_infinity: *const c_void,
        npoints: usize,
        scalars: *const c_void,
        ffi_affine_sz: usize,
    ) -> cuda::Error;
}

///////////////////////////////////////////////////////////////////////////////
// Rust functions
///////////////////////////////////////////////////////////////////////////////

// The C++ reads `fr_t` as 32 bytes, an affine point as 104 bytes with
// `infinity` at byte 96, and writes `point_t` as 144 bytes.
const _: () = assert!(
    size_of::<Fr>() == 32
        && size_of::<BigInteger256>() == 32
        && size_of::<G1Affine>() == 104
        && std::mem::offset_of!(G1Affine, infinity) == 96
        && size_of::<G1Projective>() == 144
);

/// Panics unless `T` is `Expected`. The FFI takes `c_void` pointers and the C++
/// is compiled for BLS12-377, so another type of the same width, such as
/// another curve's scalar field, would be computed with the wrong modulus.
#[track_caller]
fn assert_type<T: 'static, Expected: 'static>() {
    assert!(
        TypeId::of::<T>() == TypeId::of::<Expected>(),
        "the C++ reads this as {}, got {}",
        std::any::type_name::<Expected>(),
        std::any::type_name::<T>()
    );
}

/// Compute an in-place NTT on the input data.
#[allow(non_snake_case)]
pub fn NTT<T: 'static>(
    domain_size: usize,
    inout: &mut [T],
    ntt_order: NTTInputOutputOrder,
    ntt_direction: NTTDirection,
    ntt_type: NTTType,
) -> Result<(), cuda::Error> {
    assert_type::<T, Fr>();
    // Zero passes the power-of-two test, and `trailing_zeros()` is then 64,
    // which the C++ shifts by.
    if domain_size == 0 || (domain_size & (domain_size - 1)) != 0 {
        panic!("domain_size must be a non-zero power of 2, got {domain_size}");
    }
    // The C++ reads and writes `domain_size` elements through this pointer.
    assert_eq!(inout.len(), domain_size, "the buffer must be exactly the domain the NTT runs over");
    let lg_domain_size = domain_size.trailing_zeros();

    let err = unsafe {
        snarkvm_ntt(inout.as_mut_ptr() as *mut core::ffi::c_void, lg_domain_size, ntt_order, ntt_direction, ntt_type)
    };

    if err.code != 0 {
        return Err(err);
    }
    Ok(())
}

/// Whether [`polymul`] can multiply this many operands over a domain of this
/// size. Two or more operands over a one-element domain reach
/// `Polynomial::Mul`, which launches `1 << 31` threads for it.
pub fn polymul_supports(domain_size: usize, operands: usize) -> bool {
    domain_size > 1 || operands < 2
}

/// Compute a polynomial multiply
pub fn polymul<T: std::clone::Clone + 'static>(
    domain: usize,
    polynomials: &Vec<Vec<T>>,
    evaluations: &Vec<Vec<T>>,
    zero: &T,
) -> Result<Vec<T>, cuda::Error> {
    assert_type::<T, Fr>();
    let initial_domain_size = domain;
    if initial_domain_size == 0 || (initial_domain_size & (initial_domain_size - 1)) != 0 {
        panic!("domain_size must be a non-zero power of 2, got {initial_domain_size}");
    }
    assert!(
        polymul_supports(initial_domain_size, polynomials.len() + evaluations.len()),
        "Polynomial::Mul cannot multiply {} operands over a one-element domain",
        polynomials.len() + evaluations.len()
    );
    // The C++ copies each polynomial into a domain-sized buffer, and reads
    // each evaluation as a full domain.
    assert!(
        polynomials.iter().all(|p| p.len() <= initial_domain_size),
        "a polynomial is longer than the domain of {initial_domain_size}"
    );
    assert!(
        evaluations.iter().all(|e| e.len() == initial_domain_size),
        "an evaluation does not fill the domain of {initial_domain_size}"
    );

    let lg_domain_size = initial_domain_size.trailing_zeros();

    let mut pptrs = Vec::new();
    let mut plens = Vec::new();
    for polynomial in polynomials {
        pptrs.push(polynomial.as_ptr() as *const core::ffi::c_void);
        plens.push(polynomial.len());
    }
    let mut eptrs = Vec::new();
    let mut elens = Vec::new();
    for evaluation in evaluations {
        eptrs.push(evaluation.as_ptr() as *const core::ffi::c_void);
        elens.push(evaluation.len());
    }

    let mut out = Vec::new();
    out.resize(initial_domain_size, zero.clone());
    let err = unsafe {
        snarkvm_polymul(
            out.as_mut_ptr() as *mut core::ffi::c_void,
            pptrs.len(),
            pptrs.as_ptr() as *const core::ffi::c_void,
            plens.as_ptr() as *const core::ffi::c_void,
            eptrs.len(),
            eptrs.as_ptr() as *const core::ffi::c_void,
            elens.as_ptr() as *const core::ffi::c_void,
            lg_domain_size,
        )
    };

    if err.code != 0 {
        return Err(err);
    }
    Ok(out)
}

/// Compute a multi-scalar multiplication
pub fn msm<Affine: 'static, Projective: 'static, Scalar: 'static>(
    points: &[Affine],
    scalars: &[Scalar],
) -> Result<Projective, cuda::Error> {
    assert_type::<Affine, G1Affine>();
    assert_type::<Projective, G1Projective>();
    assert_type::<Scalar, BigInteger256>();

    let npoints = scalars.len();
    if npoints > points.len() {
        panic!("length mismatch {} points < {} scalars", npoints, scalars.len())
    }
    let mut ret = std::mem::MaybeUninit::<Projective>::uninit();
    let err = unsafe {
        snarkvm_msm(
            ret.as_mut_ptr() as *mut c_void,
            points as *const _ as *const c_void,
            npoints,
            scalars as *const _ as *const c_void,
            std::mem::size_of::<Affine>(),
        )
    };
    if err.code != 0 {
        return Err(err);
    }
    // SAFETY: the C++ writes `*out` whenever it returns success.
    Ok(unsafe { ret.assume_init() })
}

/// The CPU features blst's routines run with. Bit 0 is ADX.
#[doc(hidden)]
pub fn blst_platform_cap() -> i32 {
    unsafe { snarkvm_blst_platform_cap() }
}
