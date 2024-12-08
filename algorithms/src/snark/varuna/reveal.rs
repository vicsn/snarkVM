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

use std::sync::Arc;

impl Reveal for VarunaHidingMode {
    type Base = VarunaHidingMode;

    fn reveal(self) -> Self::Base {
        self
    }

    fn from_add_shared(b: Self::Base) -> Self {
        b
    }

    fn from_public(b: Self::Base) -> Self {
        b
    }
}

impl Reveal for CircuitId {
    type Base = CircuitId;

    fn reveal(self) -> Self::Base {
        CircuitId(self.0)
    }

    fn from_add_shared(b: Self::Base) -> Self {
        Self(b.0)
    }

    fn from_public(b: Self::Base) -> Self {
        Self(b.0)
    }
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for BatchProof<MpcPairingEngine<E, PS>> 
where 
    <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>,
{
    type Base = BatchProof<E>;

    fn reveal(self) -> Self::Base {
        BatchProof::<E>(self.0.reveal())
    }

    fn from_add_shared(b: Self::Base) -> Self {
        Self(Reveal::from_add_shared(b.0))
    }

    fn from_public(b: Self::Base) -> Self {
        Self(Reveal::from_public(b.0))
    }
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for kzg10::KZGCommitment<MpcPairingEngine<E, PS>> 
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = kzg10::KZGCommitment<E>;

    fn reveal(self) -> Self::Base {
        kzg10::KZGCommitment(self.0.reveal())
    }

    fn from_add_shared(b: Self::Base) -> Self {
        kzg10::KZGCommitment(<MpcPairingEngine<E, PS> as PairingEngine>::G1Affine::from_add_shared(b.0))
    }

    fn from_public(b: Self::Base) -> Self {
        kzg10::KZGCommitment(<MpcPairingEngine<E, PS> as PairingEngine>::G1Affine::from_public(b.0))
    }
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for kzg10::KZGProof<MpcPairingEngine<E, PS>> 
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = kzg10::KZGProof<E>;
    struct_reveal_simp_impl!(kzg10::KZGProof; w, random_v);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for WitnessCommitments<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = WitnessCommitments<E>;
    struct_reveal_simp_impl!(WitnessCommitments; w);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for Commitments<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = Commitments<E>;
    struct_reveal_simp_impl!(Commitments; witness_commitments, mask_poly, h_0, g_1, h_1, g_a_commitments, g_b_commitments, g_c_commitments, h_2);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>>
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = Evaluations<F>;
    struct_reveal_simp_impl!(Evaluations; g_1_eval, g_a_evals, g_b_evals, g_c_evals);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for MatrixSums<MpcField<F, S>>
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = MatrixSums<F>;
    struct_reveal_simp_impl!(MatrixSums; sum_a, sum_b, sum_c);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for ThirdMessage<MpcField<F, S>>
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = ThirdMessage<F>;
    struct_reveal_simp_impl!(ThirdMessage; sums);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for FourthMessage<MpcField<F, S>>
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = FourthMessage<F>;
    struct_reveal_simp_impl!(FourthMessage; sums);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for BatchLCProof<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = BatchLCProof<E>;
    struct_reveal_simp_impl!(BatchLCProof; proof);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for Proof<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
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

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for CircuitVerifyingKey<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = CircuitVerifyingKey<E>;
    struct_reveal_simp_impl!(CircuitVerifyingKey; circuit_info, circuit_commitments, id);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for Circuit<MpcField<F, S>, VarunaHidingMode> 
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = Circuit<F, VarunaHidingMode>;
    struct_reveal_simp_impl!(Circuit; index_info, a, b, c, a_arith, b_arith, c_arith, fft_precomputation, ifft_precomputation, _mode, id);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for MatrixEvals<MpcField<F, S>>
where <MpcField<F, S> as PrimeField>::BigInteger: From<MpcField<F, S>>
{
    type Base = MatrixEvals<F>;
    struct_reveal_simp_impl!(MatrixEvals; row, col, row_col, row_col_val);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for CommitterKey<MpcPairingEngine<E, PS>>
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = CommitterKey<E>;
    struct_reveal_simp_impl!(CommitterKey; powers_of_beta_g, lagrange_bases_at_beta_g, powers_of_beta_times_gamma_g, shifted_powers_of_beta_g, shifted_powers_of_beta_times_gamma_g, enforced_degree_bounds);
}

impl<E: PairingEngine, PS: PairingShare<E>> Reveal for CircuitProvingKey<MpcPairingEngine<E, PS>, VarunaHidingMode> 
where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
{
    type Base = CircuitProvingKey<E, VarunaHidingMode>;

    fn reveal(self) -> Self::Base {
        let CircuitProvingKey {
            circuit_verifying_key,
            circuit,
            committer_key,
        } = self;
        CircuitProvingKey::<E, VarunaHidingMode> {
            circuit_verifying_key: circuit_verifying_key.reveal(),
            circuit: Arc::new(Arc::into_inner(circuit).unwrap().reveal()),
            committer_key: Arc::new(Arc::into_inner(committer_key).unwrap().reveal()),
        }
    }

    fn from_add_shared(b: Self::Base) -> Self {
        let CircuitProvingKey {
            circuit_verifying_key,
            circuit,
            committer_key,
        } = b;
        Self {
            circuit_verifying_key: Reveal::from_add_shared(circuit_verifying_key),
            circuit: Arc::new(Reveal::from_add_shared(Arc::into_inner(circuit).unwrap())),
            committer_key: Arc::new(Reveal::from_add_shared(Arc::into_inner(committer_key).unwrap())),
        }
    }

    fn from_public(b: Self::Base) -> Self {
        let CircuitProvingKey {
            circuit_verifying_key,
            circuit,
            committer_key,
        } = b;
        Self {
            circuit_verifying_key: Reveal::from_public(circuit_verifying_key),
            circuit: Arc::new(Reveal::from_public(Arc::into_inner(circuit).unwrap())),
            committer_key: Arc::new(Reveal::from_public(Arc::into_inner(committer_key).unwrap())),
        }
    }
}

// impl<E: PairingEngine, PS: PairingShare<E>> Reveal for CircuitProvingKey<MpcPairingEngine<E, PS>, VarunaHidingMode>
// where <MpcField<E::Fr, PS::FrShare> as PrimeField>::BigInteger: From<MpcField<E::Fr, PS::FrShare>>
// {
//     type Base = CircuitProvingKey<E, VarunaHidingMode>;
//     struct_reveal_simp_impl!(CircuitProvingKey; circuit_verifying_key, circuit, committer_key);
// }
