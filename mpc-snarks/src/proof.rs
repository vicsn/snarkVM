#![allow(dead_code)]
#![allow(unused_imports)]
use snarkvm_curves::PairingEngine;
use snarkvm_utilities::TestRng;
use snarkvm_fields::Field;
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
    fn local<E: PairingEngine>(n: usize, timer_label: &str);
    fn ark_local<E: PairingEngine>(_n: usize, _timer_label: &str) {
        unimplemented!("ark benchmark for {}", std::any::type_name::<Self>())
    }
    fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str);
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
        // use ark_marlin::Marlin;
        // use ark_marlin::*;
        // use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
        use snarkvm_algorithms::{crypto_hash::PoseidonSponge, fft::DensePolynomial, snark::varuna::{AHPForR1CS, CircuitProvingKey, VarunaHidingMode, VarunaSNARK}, AlgebraicSponge, SNARK};
        use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
        use snarkvm_circuit::{prelude::{Field, *}, Environment, network::AleoV0};
        use snarkvm_utilities::TestRng;

        // type KzgMarlin<Fr, E> = Marlin<Fr, MarlinKZG10<E, DensePolynomial<Fr>>, Blake2s>;

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
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
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

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) { // Key entrypoint

                let snarkvm_rng = &mut TestRng::default();
                type VarunaInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;
                type FS = PoseidonSponge<Fq, 2, 1>;
                let _candidate_output = create_example_circuit::<Circuit>();
                let assignment = Circuit::eject_assignment_and_reset();
                let max_degree = 300;
                let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
                let universal_prover = &universal_srs.to_universal_prover().unwrap();
                let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
                let fs_pp = FS::sample_parameters();
                let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &assignment).unwrap();
                
                // let mpc_pk = CircuitProvingKey::from_public(index_pk);

                // TODO: look at how all inputs needs to be parameterized.
                // TODO: especially Assignment. We call generate_constraints still during proving. But perhaps, that is just a plain local linear transformation, so no worries.
                let proof = VarunaInst::prove(universal_prover, &fs_pp, &index_pk, &assignment, snarkvm_rng).unwrap();
                let one = <Circuit as Environment>::BaseField::one();
                VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, [one, one + one], &proof).unwrap();

                // let rng = &mut TestRng::default();
                // let circ_no_data = RepeatedSquaringCircuit::without_data(n);
                // let srs = KzgMarlin::<E::Fr, E>::universal_setup(n, n + 2, 3 * n, rng).unwrap();

                // let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_no_data).unwrap();
                // let mpc_pk = IndexProverKey::from_public(pk);

                // use ark_ff::One;
                // let a = E::Fr::one() + E::Fr::one(); //rand(rng);
                // let computation_timer = start_timer!(|| "do the mpc (cheat)");
                // let circ_data = mpc_squaring_circuit::<
                //     E::Fr,
                //     <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                // >(a, n);
                // let public_inputs = vec![circ_data.chain.first().unwrap().unwrap().reveal()];
                // end_timer!(computation_timer);

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
            let mut vars: Vec<Variable> = self
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
