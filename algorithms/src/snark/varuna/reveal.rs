#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]

// use ark_ff::Field;
// use ark_ec::PairingEngine;
// use ark_poly::univariate::DensePolynomial;
// use ark_poly_commit::marlin_pc::MarlinKZG10;
// use ark_poly_commit::reveal as pc_reveal;
// use blake2::Blake2s;
// use mpc_algebra::*;
// use Marlin;

use super::*;
// use crate::ahp::*;
// use ark_poly::EvaluationDomain;
use aleo_std::{end_timer, start_timer};
use mpc_algebra::{Reveal, struct_reveal_simp_impl, MpcPairingEngine, PairingShare, FieldShare, MpcField};
use crate::polycommit::sonic_pc::{BatchProof, BatchLCProof, CommitterKey};
use crate::polycommit::*;
use crate::snark::varuna::prover::*;
use snarkvm_fft::fft::domain::{FFTPrecomputation, IFFTPrecomputation};
use crate::snark::varuna::matrices::MatrixEvals;
use snarkvm_curves::PairingEngine;
use snarkvm_fields::PrimeField;

impl<E: PairingEngine, S: PairingShare<E>> Reveal for BatchProof<MpcPairingEngine<E, S>> {
    type Base = BatchProof<E>;

    fn reveal(self) -> Self::Base {
        BatchProof::<E>(self.0.reveal())
    }

    fn from_add_shared(b: Self::Base) -> Self {
        BatchProof::<E>(Reveal::from_add_shared(b.0))
    }

    fn from_public(b: Self::Base) -> Self {
        BatchProof::<E>(Reveal::from_public(b.0))
    }
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for kzg10::KZGCommitment<MpcPairingEngine<E, S>> {
    type Base = kzg10::KZGCommitment<E>;

    fn reveal(self) -> Self::Base {
        kzg10::KZGCommitment(self.0.reveal())
    }

    fn from_add_shared(b: Self::Base) -> Self {
        kzg10::KZGCommitment(<MpcPairingEngine<E, S> as PairingEngine>::G1Affine::from_add_shared(b.0))
    }

    fn from_public(b: Self::Base) -> Self {
        kzg10::KZGCommitment(<MpcPairingEngine<E, S> as PairingEngine>::G1Affine::from_public(b.0))
    }
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for kzg10::KZGProof<MpcPairingEngine<E, S>> {
    type Base = kzg10::KZGProof<E>;
    struct_reveal_simp_impl!(kzg10::KZGProof; w, random_v);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for WitnessCommitments<MpcPairingEngine<E, S>>
{
    type Base = WitnessCommitments<E>;
    struct_reveal_simp_impl!(WitnessCommitments; w);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for Commitments<MpcPairingEngine<E, S>>
{
    type Base = Commitments<E>;
    struct_reveal_simp_impl!(Commitments; witness_commitments, mask_poly, h_0, g_1, h_1, g_a_commitments, g_b_commitments, g_c_commitments, h_2);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for Evaluations<<MpcPairingEngine<E, S> as PairingEngine>::Fr>
{
    type Base = Evaluations<E::Fr>;
    struct_reveal_simp_impl!(Evaluations; g_1_eval, g_a_evals, g_b_evals, g_c_evals);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for MatrixSums<MpcField<F, S>>
{
    type Base = MatrixSums<F>;
    struct_reveal_simp_impl!(MatrixSums; sum_a, sum_b, sum_c);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for ThirdMessage<<MpcPairingEngine<E, S> as PairingEngine>::Fr>
{
    type Base = ThirdMessage<E::Fr>;
    struct_reveal_simp_impl!(ThirdMessage; sums);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for FourthMessage<<MpcPairingEngine<E, S> as PairingEngine>::Fr>
{
    type Base = FourthMessage<E::Fr>;
    struct_reveal_simp_impl!(FourthMessage; sums);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for BatchLCProof<MpcPairingEngine<E, S>>
{
    type Base = BatchLCProof<E>;
    struct_reveal_simp_impl!(BatchLCProof; proof);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for Proof<MpcPairingEngine<E, S>>
{
    type Base = Proof<E>;
    struct_reveal_simp_impl!(Proof; batch_sizes, commitments, evaluations, third_msg, fourth_msg, pc_proof);
}

impl Reveal for CircuitInfo {
    type Base = CircuitInfo;
    struct_reveal_simp_impl!(CircuitInfo;
        num_public_inputs,
        num_public_and_private_variables,
        num_constraints,
        num_non_zero_a,
        num_non_zero_b,
        num_non_zero_c
    );
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for CircuitVerifyingKey<MpcPairingEngine<E, S>>
{
    type Base = CircuitVerifyingKey<E>;
    struct_reveal_simp_impl!(CircuitVerifyingKey; circuit_info, circuit_commitments, id);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for Circuit<MpcField<F, S>, VarunaHidingMode> {
    type Base = Circuit<F, VarunaHidingMode>;
    struct_reveal_simp_impl!(Circuit; index_info, a, b, c, a_arith, b_arith, c_arith, fft_precomputation, ifft_precomputation, _mode, id);
}

impl<E: PrimeField, S: FieldShare<E>> Reveal for MatrixEvals<MpcField<E, S>>
{
    type Base = MatrixEvals<E>;
    struct_reveal_simp_impl!(MatrixEvals; row, col, row_col, row_col_val);
}
// impl<E: PrimeField, S: FieldShare<E>> Reveal for Matrix<MpcField<E, S>>
// {
//     type Base = Matrix<E>;
//     struct_reveal_simp_impl!(Matrix; row, col, val, row_col, evals_on_K, evals_on_B, row_col_evals_on_B);
// }

impl<E: PairingEngine, S: PairingShare<E>> Reveal for CommitterKey<MpcPairingEngine<E, S>>
{
    type Base = CommitterKey<E>;
    struct_reveal_simp_impl!(CommitterKey; powers_of_beta_g, lagrange_bases_at_beta_g, powers_of_beta_times_gamma_g, shifted_powers_of_beta_g, shifted_powers_of_beta_times_gamma_g, enforced_degree_bounds);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for CircuitProvingKey<MpcPairingEngine<E, S>, VarunaHidingMode>
{
    type Base = CircuitProvingKey<E, VarunaHidingMode>;
    struct_reveal_simp_impl!(CircuitProvingKey; circuit_verifying_key, circuit, committer_key);
}
