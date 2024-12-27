#![allow(dead_code)]
#![allow(unused_imports)]
use snarkvm_curves::{PairingEngine, bls12_377::{Bls12_377, Fq, Fr}};
use snarkvm_curves_package::{PairingEngine as PairingEngine2, bls12_377::{Bls12_377 as Bls12_3772, Fq as Fq2, Fr as Fr2}};
use snarkvm_utilities::{TestRng, CanonicalSerialize};
use snarkvm_utilities::{FromBytes, ToBytes};
use snarkvm_utilities_package::CanonicalDeserialize;
use snarkvm_fields::{Field, PrimeField};
use mpc_algebra::MpcField;
use snarkvm_algorithms::{r1cs::{ConstraintSystem, ConstraintSynthesizer, Variable}, prelude::SynthesisError, snark::varuna::Proof};
use snarkvm_algorithms_package::{r1cs::{ConstraintSystem as ConstraintSystem2, ConstraintSynthesizer as ConstraintSynthesizer2, Variable as Variable2}, prelude::SynthesisError as SynthesisError2, snark::varuna::Proof as Proof2};
use snarkvm_algorithms::{srs::UniversalProver, crypto_hash::PoseidonSponge, fft::DensePolynomial, snark::varuna::{AHPForR1CS, CircuitProvingKey, VarunaHidingMode, test_circuit::TestCircuit, VarunaSNARK}, AlgebraicSponge, SNARK};
use snarkvm_algorithms_package::{srs::UniversalProver as UniversalProver2, crypto_hash::PoseidonSponge as PoseidonSponge2, fft::DensePolynomial as DensePolynomial2, snark::varuna::{AHPForR1CS as AHPForR1CS2, CircuitProvingKey as CircuitProvingKey2, VarunaHidingMode as VarunaHidingMode2, VarunaSNARK as VarunaSNARK2}, AlgebraicSponge as AlgebraicSponge2, SNARK as SNARK2};
use snarkvm_utilities::Uniform;
use snarkvm_fields::MpcWire;

use aleo_std::{end_timer, start_timer};
use blake2::Blake2s;
use clap::arg_enum;
use log::debug;
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};
use mpc_net::{MpcMultiNet, MpcNet, MpcTwoNet};
use structopt::StructOpt;

use std::path::PathBuf;

mod test_circuit;

const TIMED_SECTION_LABEL: &str = "timed section";

fn mpc<E: PairingEngine, S: PairingShare<E>>() {

    println!("START LOCAL TEST");
    type VarunaInst<E> = VarunaSNARK::<E, PoseidonSponge<<E as PairingEngine>::Fq, 2, 1>, VarunaHidingMode>;
    let mul_depth = 2;
    let num_constraints = 8;
    let num_variables = 8;
    let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng
    let (circuit, public_inputs) = TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, snarkvm_rng);
    let max_degree = 300;
    let universal_srs = VarunaInst::<E>::universal_setup(max_degree).unwrap();
    let universal_prover = &universal_srs.to_universal_prover().unwrap();
    let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
    let fs_pp = PoseidonSponge::<E::Fq, 2, 1>::sample_parameters();
    let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap();

    let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng 
    let proof = VarunaInst::prove(universal_prover, &fs_pp, &index_pk, &circuit, snarkvm_rng).unwrap().0;
    let result = VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, public_inputs.clone(), &proof).unwrap();
    assert!(result);

    println!("START MPC TEST");
    type MpcVarunaInst<E, S> = VarunaSNARK::<MpcPairingEngine<E, S>, PoseidonSponge<<MpcPairingEngine<E, S> as PairingEngine>::Fq, 2, 1>, VarunaHidingMode>;
    let timer = start_timer!(|| TIMED_SECTION_LABEL);
    let mpc_circuit = TestCircuit::<MpcField<<E as PairingEngine>::Fr, S::FrShare>>::king_share(circuit, snarkvm_rng); // TODO: we'll have to split among users.
    let mpc_fs_pp = PoseidonSponge::<<MpcPairingEngine::<E, S> as PairingEngine>::Fq, 2, 1>::sample_parameters();
    let mpc_pk = CircuitProvingKey::from_public(index_pk);
    let mpc_universal_prover = UniversalProver::<MpcPairingEngine<E, S>>::from_public(universal_prover.clone());
    MpcMultiNet::reset_stats();
    let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng 
    let proof = channel::without_cheating(|| {
        let (proof, _comm_test, _oracle_test, _z_a, _w) = MpcVarunaInst::prove(&mpc_universal_prover, &mpc_fs_pp, &mpc_pk, &mpc_circuit, snarkvm_rng).unwrap();
        proof.reveal()
    });
    let result = VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, public_inputs, &proof).unwrap();
    assert!(result);

    end_timer!(timer);

    println!("START PACKAGE TEST");
    type VarunaInst2<E> = VarunaSNARK2::<E, PoseidonSponge2<<E as PairingEngine2>::Fq, 2, 1>, VarunaHidingMode2>;
    let snarkvm_rng = &mut TestRng::fixed(1); // TODO: this should be changed to a real rng
    let (circuit2, public_inputs2) = test_circuit::TestCircuit::gen_rand(mul_depth, num_constraints, num_variables, snarkvm_rng); // TODO: perhaps using the existing one is good enough
    let universal_srs = VarunaInst2::<Bls12_3772>::universal_setup(max_degree).unwrap();
    let universal_verifier2 = &universal_srs.to_universal_verifier().unwrap();
    let fs_pp2 = PoseidonSponge2::<<Bls12_3772 as PairingEngine2>::Fq, 2, 1>::sample_parameters();
    let (_, index_vk2) = VarunaInst2::circuit_setup(&universal_srs, &circuit2).unwrap();
    // Serialize MPC proof to bytes.
    let size = Proof::serialized_size(&proof, snarkvm_utilities::Compress::No);
    let mut serialized = vec![0; size];
    Proof::serialize_with_mode(&proof, &mut serialized[..], snarkvm_utilities::Compress::No).unwrap();
    // Deserialize stock snarkVM proof from bytes.
    let proof = Proof2::deserialize_with_mode(&serialized[..], snarkvm_utilities_package::Compress::No, snarkvm_utilities_package::Validate::No).unwrap();
    let result = VarunaInst2::verify(universal_verifier2, &fs_pp2, &index_vk2, public_inputs2, &proof).unwrap();
    assert!(result);

    println!("END TEST");
}

#[derive(Debug, StructOpt)]
struct ShareInfo {
    /// File with list of hosts
    #[structopt(long, parse(from_os_str))]
    hosts: PathBuf,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,
}

impl ShareInfo {
    fn setup(&self) {
        MpcMultiNet::init_from_file(self.hosts.to_str().unwrap(), self.party as usize)
    }
    fn teardown(&self) {
        debug!("Stats: {:#?}", MpcMultiNet::stats());
        MpcMultiNet::deinit();
    }
    fn run<E: PairingEngine>(&self) {
        mpc::<E, mpc_algebra::share::spdz::SpdzPairingShare<E>>();
    }
}

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: ShareInfo,
    },
}

impl FieldOpt {
    fn setup(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.setup(),
        }
    }
    fn teardown(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.teardown(),
        }
        println!("Stats: {:#?}", MpcMultiNet::stats());
    }
    fn run<E: PairingEngine>(
        &self,
    ) {
        self.setup();
        match self {
            FieldOpt::Mpc { party_info, .. } => {
                party_info.run::<E>()
            }
        }
        self.teardown();
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "proof", about = "Standard and MPC proofs")]
struct Opt {
    #[structopt(subcommand)]
    field: FieldOpt,
}

impl Opt {}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    opt.field.run::<Bls12_377>();
}
