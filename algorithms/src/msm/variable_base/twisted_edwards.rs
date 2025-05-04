// Copyright (c) 2019-2025 Provable Inc.
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

use std::str::FromStr;
// use ark_ff::Field;
// use ark_std::{One, Zero};
use snarkvm_fields::{Field, One, PrimeField, Zero};
use snarkvm_utilities::{io, FromBytes, Read, ToBytes, Write};

use snarkvm_curves::{
    bls12_377::{Fq, G1Affine},
    traits::AffineCurve,
};

use snarkvm_utilities::{CanonicalSerialize, CanonicalDeserialize};

lazy_static::lazy_static! {
    pub static ref MONT_ALPHA: Fq = Fq::from_str("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946").unwrap();
    pub static ref MONT_BETA: Fq = Fq::from_str("207913745465435703873309001080708636764682407053260289242004673792544811711776497012639468972230205966814119707502").unwrap();

    // these two parameters define a twisted edwards curve: a * X^2 + Y^2 = 1 + d * X^2 * Y^2
    pub static ref ED_COEFF_A: Fq = Fq::from_str("157163064917902313978814213261261898218646390773518349738660969080500653509624033038447657619791437448628296189665").unwrap();
    pub static ref ED_COEFF_D: Fq = Fq::from_str("101501361095066780517536410023107951769097300825221174390295061910482811707540513312796446149590693954692781734188").unwrap();

    // to make calculations even faster, we are actually manipulating on the curve: -X^2 + Y^2 = 1 + (-d / a) * X^2 * Y^2
    // thus, renaming (-d / a) to `dd`, we get another curve: -X^2 + Y^2 = 1 + dd * X^2 * Y^2
    // we need `k = 2 * dd` in unified addition, so we save it here:
    pub static ref ED_COEFF_DD: Fq = Fq::from_str("136396142414293534522166394536258004439411625840037520960350109084686791562955032044926524798337324377515360555012").unwrap();
    pub static ref ED_COEFF_K: Fq = Fq::from_str("14127858815617975033680055377622475342429738925160381380815955502653114777569241314884161457101288630590399651847").unwrap();

    // in order to do coordinates transform, we need `sqrt(-a)`
    pub static ref ED_COEFF_SQRT_NEG_A: Fq = Fq::from_str("237258690121739794091542072758217926613126300728951001700615245829450947395696022962309165363059235018940120114447").unwrap();
    pub static ref ED_COEFF_SQRT_NEG_A_INV: Fq = Fq::from_str("85493388116597753391764605746615521878764370024930535315959456146985744891605502660739892967955718798310698221510").unwrap();

    pub static ref FQ_TWO: Fq = Fq::from(2u64);
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct SwAffine {
    pub x: Fq,
    pub y: Fq,
}

/// for Edwards curves
#[derive(Copy, Clone, Debug, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize, Eq)]
#[repr(C)]
pub struct EdAffine {
    pub x: Fq,
    pub y: Fq,
    pub t: Fq,
}

impl Default for EdAffine {
    fn default() -> Self {
        let x = Fq::zero();
        let y = Fq::one();
        let t = Fq::zero();
        Self { x, y, t }
    }
}

impl ToBytes for EdAffine {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.x.write_le(&mut writer)?;
        self.y.write_le(&mut writer)?;
        self.t.write_le(&mut writer)
    }
}

impl FromBytes for EdAffine {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        let x = Fq::read_le(&mut reader)?;
        let y = Fq::read_le(&mut reader)?;
        let t = Fq::read_le(&mut reader)?;

        Ok(Self { x, y, t })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct EdProjective {
    pub x: Fq,
    pub y: Fq,
    pub t: Fq,
    pub z: Fq,
}

impl Default for EdProjective {
    fn default() -> Self {
        let x = Fq::zero();
        let y = Fq::one();
        let t = Fq::zero();
        let z = Fq::one();

        Self { x, y, t, z }
    }
}

impl EdProjective {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn add_assign(&mut self, other: &EdProjective) {
        let (_, k) = get_dd_k();

        // doing add arithmetic
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = k * self.t * other.t;
        let d = (self.z * other.z).double();

        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;

        self.x = e * f;
        self.y = g * h;
        self.t = e * h;
        self.z = f * g;
    }

    pub fn double_in_place(&mut self) {
        // doing add arithmetic
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let d = -a;

        let e = (self.x + self.y).square() - a - b;
        let g = d + b;
        let f = g - c;
        let h = d - b;

        self.x = e * f;
        self.y = g * h;
        self.t = e * h;
        self.z = f * g;
    }

    pub fn add_assign_mixed(&mut self, other: &EdAffine) {
        let (_, k) = get_dd_k();

        // doing add arithmetic
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = k * self.t * other.t;
        let d = self.z.double();

        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;

        self.x = e * f;
        self.y = g * h;
        self.t = e * h;
        self.z = f * g;
    }
}

#[inline]
fn get_alpha_beta() -> (Fq, Fq) {
    (*MONT_ALPHA, *MONT_BETA)
}

#[inline]
fn get_a_d() -> (Fq, Fq) {
    (*ED_COEFF_A, *ED_COEFF_D)
}

#[inline]
fn get_dd_k() -> (Fq, Fq) {
    (*ED_COEFF_DD, *ED_COEFF_K)
}

#[inline]
fn get_sqrt_neg_a() -> (Fq, Fq) {
    (*ED_COEFF_SQRT_NEG_A, *ED_COEFF_SQRT_NEG_A_INV)
}

/// we don't introduce new Rust struct here, instead we reuse `EdAffine` to represent the new coordinates under `-x^2 + y^2 = 1 + dd * x^2 * y^2`
#[allow(unused)]
pub(crate) fn edwards_to_neg_one_a(ed: EdAffine) -> EdAffine {
    let (divisor, _) = get_sqrt_neg_a();

    let t = ed.x * divisor * ed.y;

    EdAffine { x: ed.x * divisor, y: ed.y, t }
}

/// we don't introduce new Rust struct here, instead we reuse `EdAffine` to represent the new coordinates under `-x^2 + y^2 = 1 + dd * x^2 * y^2`
#[allow(unused)]
pub(crate) fn edwards_from_neg_one_a(ed: EdAffine) -> EdAffine {
    let (_, multiplier) = get_sqrt_neg_a();

    let t = ed.x * multiplier * ed.y;

    EdAffine { x: ed.x * multiplier, y: ed.y, t }
}

#[allow(unused)]
pub(crate) fn sw_to_edwards<G: AffineCurve>(g: &G) -> EdAffine {
    let (alpha, beta) = get_alpha_beta();

    let sw_g = unsafe { std::mem::transmute::<&G, &SwAffine>(g) };

    // first convert sw to montgomery form
    let mont_x = (sw_g.x - alpha) / beta;
    let mont_y = sw_g.y / beta;

    // then from mont to edwards form
    let one = Fq::one();

    // map sw curve infinity point to te curve inf point
    if mont_y.is_zero() || (mont_x + one).is_zero() {
        return EdAffine::default();
    }

    let ed_x = mont_x / mont_y;
    let ed_y = (mont_x - one) / (mont_x + one);
    let ed_t = ed_x * ed_y;

    EdAffine { x: ed_x, y: ed_y, t: ed_t }
}

#[allow(unused)]
pub(crate) fn edwards_to_sw<G: AffineCurve>(ed: EdAffine) -> G {
    let (alpha, beta) = get_alpha_beta();

    // first convert ed form to mont form
    let one = Fq::one();

    if (one - ed.y).is_zero() || ed.x.is_zero() {
        return G::default();
    }

    let mont_x = (one + ed.y) / (one - ed.y);
    let mont_y = (one + ed.y) / (ed.x - ed.x * ed.y);

    // then from mont form to sw form
    let g_x = mont_x * beta + alpha;
    let g_y = mont_y * beta;

    let sw_g = SwAffine { x: g_x, y: g_y };

    let &g = unsafe { std::mem::transmute::<&SwAffine, &G>(&sw_g) };

    g
}

#[allow(unused)]
pub(crate) fn edwards_to_sw_proj<G: AffineCurve>(ed: EdAffine) -> G::Projective {
    let (alpha, beta) = get_alpha_beta();

    // first convert ed form to mont form
    let one = Fq::one();

    if (one - ed.y).is_zero() || ed.x.is_zero() {
        return G::Projective::default();
    }

    let mont_x = (one + ed.y) / (one - ed.y);
    let mont_y = (one + ed.y) / (ed.x - ed.x * ed.y);

    // then from mont form to sw form
    let g_x = mont_x * beta + alpha;
    let g_y = mont_y * beta;

    let sw_g = SwAffine { x: g_x, y: g_y };

    let &g = unsafe { std::mem::transmute::<&SwAffine, &G>(&sw_g) };

    g.to_projective()
}

#[allow(unused)]
pub(crate) fn edwards_affine_to_proj(ed: EdAffine) -> EdProjective {
    EdProjective { x: ed.x, y: ed.y, t: ed.x * ed.y, z: Fq::one() }
}

#[allow(unused)]
pub(crate) fn edwards_proj_to_affine(ed: EdProjective) -> EdAffine {
    if ed.z.is_zero() {
        return EdAffine::default();
    }

    let x = ed.x / ed.z;
    let y = ed.y / ed.z;

    EdAffine { x, y, t: x * y }
}
