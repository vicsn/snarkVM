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

use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{One, PrimeField, Zero};
use snarkvm_utilities::{cfg_into_iter, BigInteger};

use crate::msm::twisted_edwards::*;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

// we transform `T` to arkworks' `G1Affine`
pub fn generate_ed_bases<G: AffineCurve>(bases: &[G]) -> Vec<EdAffine> {
    use snarkvm_curves::bls12_377::{G1Affine, G1Projective};

    let n = bases.len();
    let tbases = unsafe { std::mem::transmute::<_, &[G1Affine]>(bases) };

    let mut precalc_table = vec![EdAffine::default(); n];

    let best_chunk = if n > 1000 { 1000 } else { 1 };

    precalc_table.par_chunks_mut(best_chunk).enumerate().for_each(|(idx, b_vec)| {
        let start = idx * best_chunk;

        for i in 0..b_vec.len() {
            // make sure z = 1
            let tmp_projective = tbases[i + start].to_projective();

            let &tmp_projective = unsafe { std::mem::transmute::<_, &G1Projective>(&tmp_projective) };

            let ed = sw_to_edwards(&tbases[i + start]);
            let ed = edwards_to_neg_one_a(ed);

            b_vec[i] = ed;
        }
    });

    precalc_table
}

fn te_update_buckets<G: AffineCurve>(
    base: &EdAffine,
    mut scalar: <G::ScalarField as PrimeField>::BigInteger,
    w_start: usize,
    c: usize,
    buckets: &mut [EdProjective],
) {
    // We right-shift by w_start, thus getting rid of the lower bits.
    scalar.divn(w_start as u32);

    // We mod the remaining bits by the window size.
    let scalar = scalar.as_ref()[0] % (1 << c);

    // If the scalar is non-zero, we update the corresponding bucket.
    // (Recall that `buckets` doesn't have a zero bucket.)
    if scalar != 0 {
        buckets[(scalar - 1) as usize].add_assign_mixed(base);
    }
}

fn te_standard_window<G: AffineCurve>(
    bases: &[EdAffine],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
    w_start: usize,
    c: usize,
) -> (EdProjective, usize) {
    let mut res = EdProjective::zero();
    let fr_one = G::ScalarField::one().to_bigint();

    // We only process unit scalars once in the first window.
    if w_start == 0 {
        scalars.iter().zip(bases).filter(|(&s, _)| s == fr_one).for_each(|(_, base)| {
            res.add_assign_mixed(base);
        });
    }

    // We don't need the "zero" bucket, so we only have 2^c - 1 buckets
    let window_size = if (w_start % c) != 0 { w_start % c } else { c };
    let mut buckets = vec![EdProjective::zero(); (1 << window_size) - 1];
    scalars
        .iter()
        .zip(bases)
        .filter(|(&s, _)| s > fr_one)
        .for_each(|(&scalar, base)| te_update_buckets::<G>(base, scalar, w_start, c, &mut buckets));
    // G::Projective::batch_normalization(&mut buckets);

    for running_sum in buckets.into_iter().rev().scan(EdProjective::zero(), |sum, b| {
        sum.add_assign(&b);
        Some(*sum)
    }) {
        res.add_assign(&running_sum);
    }

    (res, window_size)
}

pub fn te_msm<G: AffineCurve>(
    bases: &[EdAffine],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
) -> G::Projective {
    // Determine the bucket size `c` (chosen empirically).
    let c = match scalars.len() < 32 {
        true => 1,
        false => crate::msm::ln_without_floats(scalars.len()) + 2,
    };

    let num_bits = <G::ScalarField as PrimeField>::size_in_bits();

    // Each window is of size `c`.
    // We divide up the bits 0..num_bits into windows of size `c`, and
    // in parallel process each such window.
    let window_sums: Vec<_> = cfg_into_iter!(0..num_bits)
        .step_by(c)
        .map(|w_start| te_standard_window::<G>(bases, scalars, w_start, c))
        .collect();

    // We store the sum for the lowest window.
    let (lowest, window_sums) = window_sums.split_first().unwrap();

    // We're traversing windows from high to low.
    let mut res = window_sums.iter().rev().fold(EdProjective::zero(), |mut total, (sum_i, window_size)| {
        total.add_assign(&sum_i);
        for _ in 0..*window_size {
            total.double_in_place();
        }
        total
    });
    res.add_assign(&lowest.0);

    let sw_g = edwards_to_sw_proj::<G>(edwards_from_neg_one_a(edwards_proj_to_affine(res)));
    let &g = unsafe { std::mem::transmute::<_, &G::Projective>(&sw_g) };

    g
}
