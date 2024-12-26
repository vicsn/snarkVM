#![allow(dead_code)]
#![allow(unused_imports)]
use snarkvm_curves::PairingEngine;
use snarkvm_utilities::TestRng;
use snarkvm_fields::{Field, PrimeField};
use mpc_algebra::MpcField;
use snarkvm_algorithms::r1cs::ConstraintSynthesizer;
use snarkvm_algorithms::prelude::SynthesisError;
use snarkvm_algorithms::r1cs::Variable;
use snarkvm_curves::bls12_377::Bls12_377;

use aleo_std::{end_timer, start_timer};
use blake2::Blake2s;
use clap::arg_enum;
use log::debug;
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};
use mpc_net::{MpcMultiNet, MpcNet, MpcTwoNet};
use structopt::StructOpt;

use std::path::PathBuf;

mod marlin;
mod silly;

const TIMED_SECTION_LABEL: &str = "timed section";

trait SnarkBench {
    fn local<E: PairingEngine>(_n: usize, _timer_label: &str);
    fn ark_local<E: PairingEngine>(_n: usize, _timer_label: &str) {
        unimplemented!("ark benchmark for {}", std::any::type_name::<Self>())
    }
    fn mpc<
        E: PairingEngine,
        S: PairingShare<E>
    >(_n: usize, timer_label: &str);
}

mod squarings {
    use super::*;
    #[derive(Clone)]
    struct RepeatedSquaringCircuit<F: Field> {
        chain: Vec<Option<F>>,
    }

    impl<F: Field> RepeatedSquaringCircuit<F> {
        fn without_data(squarings: usize) -> Self {
            Self {
                chain: vec![None; squarings + 1],
            }
        }
        fn from_start(f: F, squarings: usize) -> Self {
            let mut chain = vec![Some(f)];
            for _ in 0..squarings {
                let mut last = chain.last().unwrap().as_ref().unwrap().clone();
                last.square_in_place();
                chain.push(Some(last));
            }
            Self { chain }
        }
        fn from_chain(f: Vec<F>) -> Self {
            Self {
                chain: f.into_iter().map(Some).collect(),
            }
        }
        fn squarings(&self) -> usize {
            self.chain.len() - 1
        }
    }

    pub mod marlin {
        use super::*;
        use snarkvm_algorithms::{crypto_hash::PoseidonSponge, fft::DensePolynomial, snark::varuna::{AHPForR1CS, CircuitProvingKey, VarunaHidingMode, test_circuit::TestCircuit, VarunaSNARK}, AlgebraicSponge, SNARK};
        use snarkvm_algorithms::srs::UniversalProver;
        use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
        use snarkvm_circuit::{prelude::{Field, *}, Environment, network::AleoV0};
        use snarkvm_utilities::TestRng;
        use mpc_algebra::MpcField;
        use snarkvm_utilities::Uniform;
        use snarkvm_fields::MpcWire;

        pub struct MarlinBench;

        fn create_example_circuit<E: Environment>() -> Field<E> {
            let one = snarkvm_console::types::Field::<E::Network>::one();
            let two = one + one;
    
            const REPETITIONS: u64 = 10;
    
            // Reminder: the proof system instantiates 3 more variables and constraints to make the proof hiding.
            let mut accumulator = Field::new(Mode::Public, two);
            for _ in 0..REPETITIONS {
                accumulator *= accumulator.clone();
            }
    
            assert!(E::is_satisfied());
    
            accumulator
        }

        impl SnarkBench for MarlinBench {
            fn local<E: PairingEngine>(_n: usize, _timer_label: &str) {
                unimplemented!("Local bench")
                // let rng = &mut TestRng::default();
                // let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                // let srs = KzgMarlin::<E::Fr, E>::universal_setup(n, n + 2, 3 * n, rng).unwrap();

                // let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_no_data).unwrap();

                // let a = E::Fr::rand(rng);
                // let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                // let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
                // let timer = start_timer!(|| timer_label);
                // let zk_rng = &mut test_rng();
                // let proof = KzgMarlin::<E::Fr, E>::prove(&pk, circ_data, zk_rng).unwrap();
                // end_timer!(timer);
                // assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(_n: usize, _timer_label: &str) 
            { // Key entrypoint

                type VarunaInst<E> = VarunaSNARK::<E, PoseidonSponge<<E as PairingEngine>::Fq, 2, 1>, VarunaHidingMode>;
                type MpcVarunaInst<E, S> = VarunaSNARK::<MpcPairingEngine<E, S>, PoseidonSponge<<MpcPairingEngine<E, S> as PairingEngine>::Fq, 2, 1>, VarunaHidingMode>;

                let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng

                println!("START TESTS");

                println!("START FIELD TESTS");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_2 = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field += mpc_field + mpc_field;
                mpc_field += mpc_field + mpc_field_2;
                mpc_field += mpc_field_2 + mpc_field;
                mpc_field += mpc_field_2 + mpc_field_2;
                mpc_field += &(mpc_field + &mpc_field);
                mpc_field += &(mpc_field + &mpc_field_2);
                mpc_field += &(mpc_field_2 + &mpc_field);
                mpc_field += &(mpc_field_2 + &mpc_field_2);
                mpc_field.reveal();
                println!("ADD SUCCEEDED");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_2 = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field *= mpc_field * mpc_field;
                mpc_field *= mpc_field * mpc_field_2;
                mpc_field *= mpc_field_2 * mpc_field;
                mpc_field *= mpc_field_2 * mpc_field_2;
                mpc_field_2.mul_assign(&mpc_field);
                mpc_field.mul_assign(mpc_field);
                mpc_field.mul_assign(mpc_field_2);
                mpc_field.mul_assign(&mpc_field_2);
                mpc_field.reveal();
                println!("MUL SUCCEEDED");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_shared = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field /= mpc_field / mpc_field;
                mpc_field /= mpc_field / mpc_field_shared;
                mpc_field /= mpc_field_shared / mpc_field;
                mpc_field /= mpc_field_shared / mpc_field_shared;
                mpc_field.reveal();
                println!("DIV SUCCEEDED");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_2 = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field -= mpc_field - mpc_field;
                mpc_field -= mpc_field - mpc_field_2;
                mpc_field -= mpc_field_2 - mpc_field;
                mpc_field -= mpc_field_2 - mpc_field_2;
                mpc_field.reveal();
                println!("SUB SUCCEEDED");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_2 = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field += mpc_field.double();
                mpc_field.double_in_place();
                mpc_field += mpc_field_2.double();
                mpc_field.double_in_place();
                mpc_field.reveal();
                println!("DOUBLE SUCCEEDED");
                let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                let mut mpc_field_2 = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand_shared(snarkvm_rng);
                mpc_field += mpc_field.inverse().unwrap();
                mpc_field.inverse_in_place();
                mpc_field += mpc_field_2.inverse().unwrap();
                mpc_field.inverse_in_place();
                mpc_field.reveal();
                println!("INVERSE SUCCEEDED");
                // let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng);
                // let mut mpc_bigint = mpc_field.to_bigint();
                // let mut mpc_field = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::from_bigint(mpc_bigint).unwrap();
                // mpc_field.reveal();
                // println!("BIGINT SUCCEEDED");
                let mut evals = (0..128).map(|_| <MpcPairingEngine::<E, S> as PairingEngine>::Fr::rand(snarkvm_rng)).collect::<Vec<_>>();
                let evaluation_domain = snarkvm_fft::EvaluationDomain::new(evals.len()).unwrap();
                let poly = snarkvm_fft::Evaluations::from_vec_and_domain(evals.clone(), evaluation_domain).interpolate();
                let _ = poly.reveal();
                let fft_precomputation = evaluation_domain.precompute_fft();
                let ifft_precomputation = fft_precomputation.to_ifft_precomputation();
                let poly = snarkvm_fft::Evaluations::from_vec_and_domain(evals.clone(), evaluation_domain).interpolate_with_pc(&ifft_precomputation);
                let _ = poly.reveal();
                evaluation_domain.in_order_fft_in_place_with_pc(&mut evals, &fft_precomputation);
                let poly = snarkvm_fft::Evaluations::from_vec_and_domain(evals.clone(), evaluation_domain).interpolate_with_pc(&ifft_precomputation);
                let _ = poly.reveal();
                println!("FFT SUCCEEDED");
                let small_domain = snarkvm_fft::EvaluationDomain::new(16).unwrap();
                let mut one = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::one();
                let res = small_domain.evaluate_vanishing_polynomial(one + one);
                let _ = res.reveal();
                let mut one_shared = <MpcPairingEngine::<E, S> as PairingEngine>::Fr::one_shared();
                let res = small_domain.evaluate_vanishing_polynomial(one_shared + one_shared);
                let _ = res.reveal();
                // let poly = snarkvm_fft::Evaluations::from_vec_and_domain(evals.clone(), evaluation_domain).interpolate();
                // let input_domain = snarkvm_fft::EvaluationDomain::new(8).unwrap();
                // let (poly, remainder) = poly.divide_by_vanishing_poly(input_domain).unwrap();
                // let _ = poly.reveal();
                println!("VANISHING_POLY SUCCEEDED");
                println!("START GROUP TESTS");
                let mut mpc_affine = <MpcPairingEngine::<E, S> as PairingEngine>::G1Affine::rand(snarkvm_rng);
                let mut mpc_projective = Into::<<MpcPairingEngine::<E, S> as PairingEngine>::G1Projective>::into(mpc_affine);
                mpc_projective *= mpc_field;
                mpc_projective += mpc_projective;
                mpc_affine = mpc_projective.into();
                mpc_affine.reveal();
                println!("INTO, ADD, MUL SUCCEEDED");
                // NOTE: 
                // - our witness polynomial is incorrect, what happens to it? Only field operations? See `for MpcField`
                // . - Are we even using ComField?
                // . - Are we even using MulFieldGroup?
                // . - Can we unimplemented! certain impls to see if they are used?
                // - often, mul is not supported, but mulassign is
                // - affine operations are not supported
                
       
                println!("START POLY divide_with_q_and_r TEST");
                // NOTE: for now, its easier to test here because 1. it is not currently possible to test MPC features locally 2. it even compiles faster.
                for a_degree in 0..5 {
                    for b_degree in 1..5 {
                        // NOTE: we creating shared field elements in Uniform::sample for MpcField.
                        // NOTE: for some sampling methods, values are combined using from_add_shared
                        type Fr<E, S> = <MpcPairingEngine::<E, S> as PairingEngine>::Fr;
                        let dividend = snarkvm_fft::DensePolynomial::<Fr::<E, S>>::rand(a_degree, snarkvm_rng);
                        let divisor_coeffs = (0..b_degree).map(|_| Fr::<E, S>::rand_public(snarkvm_rng)).collect::<Vec<_>>();
                        let divisor = snarkvm_fft::DensePolynomial::<Fr::<E, S>>::from_coefficients_vec(divisor_coeffs);

                        let (quotient, remainder) =
                            snarkvm_fft::Polynomial::divide_with_q_and_r(&(&dividend).into(), &(&divisor).into()).unwrap();
                        // assert_eq!(dividend, &(&divisor * &quotient) + &remainder); // This doesn't work, because due to snarkVM primitives, we end up adding Public(0)
                        println!("POLY divide_with_q_and_r {a_degree}/{b_degree} SUCCEEDED");
                    }
                }

                println!("START LOCAL TEST");
                let mul_depth = 2;
                let num_constraints = 8;
                let num_variables = 8;
                let (circuit, public_inputs) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, snarkvm_rng);
                println!("public inputs: {:?}", public_inputs);
                // NOTE: it might be theoretically possible to use a higher level Circuit crate representation...
                // let _candidate_output = create_example_circuit::<Circuit>();
                // let assignment = Circuit::eject_assignment_and_reset();

                let max_degree = 300;
                let universal_srs = VarunaInst::<E>::universal_setup(max_degree).unwrap();
                let universal_prover = &universal_srs.to_universal_prover().unwrap();
                let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
                let fs_pp = PoseidonSponge::<E::Fq, 2, 1>::sample_parameters();
                let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();

                let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng 
                let proof = VarunaInst::prove(universal_prover, &fs_pp, &index_pk, &circuit, snarkvm_rng).unwrap().0;
                println!("proof: {:?}", proof); 
                let result = VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, public_inputs.clone(), &proof).unwrap();
                assert!(result);

                println!("START MPC TEST");

                let timer = start_timer!(|| _timer_label);

                // MPC time
                let mpc_circuit = TestCircuit::<MpcField<<E as PairingEngine>::Fr, S::FrShare>>::king_share(circuit, snarkvm_rng); // TODO: we'll have to split among users.
                let mpc_fs_pp = PoseidonSponge::<<MpcPairingEngine::<E, S> as PairingEngine>::Fq, 2, 1>::sample_parameters();
                let mpc_pk = CircuitProvingKey::from_public(index_pk);
                let mpc_universal_prover = UniversalProver::<MpcPairingEngine<E, S>>::from_public(universal_prover.clone());
                MpcMultiNet::reset_stats();
                let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng 
                let proof = channel::without_cheating(|| {
                    let (proof, comm_test, oracle_test, z_a, w) = MpcVarunaInst::prove(&mpc_universal_prover, &mpc_fs_pp, &mpc_pk, &mpc_circuit, snarkvm_rng).unwrap();
                    // let _test = w.reveal();
                    // let _test = z_a.reveal();
                    // let _test = oracle_test.polynomial.as_dense().unwrap().clone().reveal();
                    // let _test = comm_test.reveal();
                    // let _test = proof.evaluations.g_a_evals.clone().publicize();
                    proof.reveal()
                });
                println!("proof: {:?}", proof);
                let result = VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, public_inputs, &proof).unwrap();
                assert!(result);

                end_timer!(timer);

                println!("END TEST");


                // let rng = &mut TestRng::default();
                // let circ_no_data = RepeatedSquaringCircuit::without_data(n);
                // let srs = KzgMarlin::<E::Fr, E>::universal_setup(n, n + 2, 3 * n, rng).unwrap();

                // let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_no_data).unwrap();
                // let mpc_pk = IndexProverKey::from_public(pk);

                // use ark_ff::One;
                // let a = E::Fr::one() + E::Fr::one(); //rand(rng);
                // let circ_data = mpc_squaring_circuit::<
                //     E::Fr,
                //     <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                // >(a, n);
                // let public_inputs = vec![circ_data.chain.first().unwrap().unwrap().reveal()];

                // MpcMultiNet::reset_stats();
                // let timer = start_timer!(|| timer_label);
                // let zk_rng = &mut test_rng();
                // let proof = channel::without_cheating(|| {
                //     KzgMarlin::<
                //         <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                //         MpcPairingEngine<E, S>,
                //     >::prove(&mpc_pk, circ_data, zk_rng)
                //     .unwrap()
                //     .reveal()
                // });
                // end_timer!(timer);
                // assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
                // // Serialize the proof to disk.
                // use std::io::Write;
                // use snarkvm_utilities::CanonicalSerialize;
                // let size = Proof::serialized_size(&proof);
                // let mut serialized = vec![0; size];
                // proof.serialize(&mut serialized[..]).unwrap();
                // let file = std::fs::File::create("proof.bin").unwrap();
                // let mut writer = std::io::BufWriter::new(file);
                // writer.write(&serialized).unwrap();
            }
        }
    }

    fn mpc_squaring_circuit<Fr: Field, MFr: Field + Reveal<Base = Fr>>(
        start: Fr,
        squarings: usize,
    ) -> RepeatedSquaringCircuit<MFr> {
        let raw_chain: Vec<Fr> = std::iter::successors(Some(start), |a| Some(a.square()))
            .take(squarings + 1)
            .collect();
        let rng = &mut TestRng::default();
        for val in raw_chain.clone() {
            println!("Circuit input: {}", val);
        }
        println!("Calling king_share_batch");
        let chain_shares = MFr::king_share_batch(raw_chain, rng);
        RepeatedSquaringCircuit {
            chain: chain_shares.into_iter().map(Some).collect(),
        }
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF>
        for RepeatedSquaringCircuit<ConstraintF>
    {
        fn generate_constraints<CS: snarkvm_algorithms::r1cs::ConstraintSystem<ConstraintF>>( // Meaningful entrypoint
            &self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> {
            // Note: at this point the values are shared.
            let mut vars = vec![];
            vars.push(cs.alloc_input(|| "input", || {
                self.chain
                    .first()
                    .unwrap()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
            let vars: Vec<Variable> = self
                .chain
                .iter()
                .skip(1)
                .take(self.squarings())
                .map(|o| cs.alloc(|| "witness",|| o.ok_or(SynthesisError::AssignmentMissing)))
                .collect::<Result<_, _>>()?;

            for i in 0..self.squarings() - 1 {
                cs.enforce(|| "constraint squaring", |lc| lc + vars[i], |lc| lc + vars[i], |lc| lc + vars[i + 1]);
            }

            Ok(())
        }
    }
}

#[derive(Debug, StructOpt)]
struct ShareInfo {
    /// File with list of hosts
    #[structopt(long, parse(from_os_str))]
    hosts: PathBuf,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,

    /// Use spdz?
    #[structopt(long)]
    alg: MpcAlg,
}

impl ShareInfo {
    fn setup(&self) {
        MpcMultiNet::init_from_file(self.hosts.to_str().unwrap(), self.party as usize)
    }
    fn teardown(&self) {
        debug!("Stats: {:#?}", MpcMultiNet::stats());
        MpcMultiNet::deinit();
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        _b: B,
        timed_label: &str,
    ) {
        match computation {
            Computation::Squaring => match self.alg {
                MpcAlg::Spdz => B::mpc::<E, mpc_algebra::share::spdz::SpdzPairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
            },
        }
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum MpcAlg {
        Spdz,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum Computation {
        Squaring,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum ProofSystem {
        Marlin,
    }
}

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: ShareInfo,
    },
    Local,
    ArkLocal,
}

impl FieldOpt {
    fn setup(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.setup(),
            _ => {}
        }
    }
    fn teardown(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.teardown(),
            _ => {}
        }
        println!("Stats: {:#?}", MpcMultiNet::stats());
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        b: B,
        timed_label: &str,
    ) {
        self.setup();
        match self {
            FieldOpt::Mpc { party_info, .. } => {
                party_info.run::<E, B>(computation, computation_size, b, timed_label)
            }
            FieldOpt::Local => B::local::<E>(computation_size, timed_label),
            FieldOpt::ArkLocal => B::ark_local::<E>(computation_size, timed_label),
        }
        self.teardown();
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "proof", about = "Standard and MPC proofs")]
struct Opt {
    /// Computation to perform
    #[structopt(short = "c")]
    computation: Computation,

    /// Proof system to use
    #[structopt(short = "p")]
    proof_system: ProofSystem,

    /// Computation to perform
    #[structopt(long, default_value = "10")]
    computation_size: usize,

    #[structopt(subcommand)]
    field: FieldOpt,
}

impl Opt {}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    match opt.proof_system {
        ProofSystem::Marlin => opt.field.run::<Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::marlin::MarlinBench,
            TIMED_SECTION_LABEL,
        ),
    }
}
