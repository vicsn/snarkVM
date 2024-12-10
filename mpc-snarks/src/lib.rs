#[cfg(test)]
mod tests {

    use snarkvm_algorithms::{AlgebraicSponge, SNARK, r1cs::ConstraintSynthesizer};
    use snarkvm_console::{
        account::{Address, PrivateKey, ViewKey},
        network::{prelude::*, MainnetV0},
        program::{Entry, Identifier, Literal, Plaintext, ProgramID, Value},
        types::U16,
    };
    use snarkvm_circuit::{Environment, network::AleoV0};
    use snarkvm_circuit::prelude::*;
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_ledger::{Ledger, RecordsFilter};
    use snarkvm_ledger_block::{Block, ConfirmedTransaction, Execution, Ratify, Rejected, Transaction};
    use snarkvm_ledger_store::{ConsensusStore, helpers::{memory, rocksdb}};
    use snarkvm_synthesizer::{Stack, program::Program, vm::VM};

    use aleo_std::StorageMode;
    use indexmap::{IndexMap, IndexSet};
    use rand::seq::SliceRandom;
    use std::collections::{BTreeMap, HashMap};
    use std::str::FromStr;
    use std::convert::TryFrom;
    
    type CurrentNetwork = MainnetV0;
    type CurrentAleo = AleoV0;

    // #[cfg(not(feature = "rocks"))]
    pub(crate) type CurrentLedger =
        Ledger<CurrentNetwork, memory::ConsensusMemory<CurrentNetwork>>;
    // #[cfg(feature = "rocks")]
    // pub(crate) type CurrentLedger = Ledger<CurrentNetwork, rocksdb::ConsensusDB<CurrentNetwork>>;

    // #[cfg(not(feature = "rocks"))]
    pub(crate) type CurrentConsensusStore =
        ConsensusStore<CurrentNetwork, memory::ConsensusMemory<CurrentNetwork>>;
    // #[cfg(feature = "rocks")]
    // pub(crate) type CurrentConsensusStore =
    //     ConsensusStore<CurrentNetwork, rocksdb::ConsensusDB<CurrentNetwork>>;

    #[allow(dead_code)]
    pub(crate) struct TestEnv {
        pub ledger: CurrentLedger,
        pub private_key: PrivateKey<CurrentNetwork>,
        pub view_key: ViewKey<CurrentNetwork>,
        pub address: Address<CurrentNetwork>,
    }

    pub(crate) fn sample_test_env(rng: &mut (impl Rng + CryptoRng)) -> TestEnv {
        // Sample the genesis private key.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let address = Address::try_from(&private_key).unwrap();
        // Sample the ledger.
        let ledger = sample_ledger(private_key, rng);
        // Return the test environment.
        TestEnv { ledger, private_key, view_key, address }
    }

    pub(crate) fn sample_genesis_block() -> Block<CurrentNetwork> {
        Block::<CurrentNetwork>::from_bytes_le(CurrentNetwork::genesis_bytes()).unwrap()
    }

    pub(crate) fn sample_ledger(
        private_key: PrivateKey<CurrentNetwork>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> CurrentLedger {
        // Initialize the store.
        let store = CurrentConsensusStore::open(None).unwrap();
        // Create a genesis block.
        let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();
        // Initialize the ledger with the genesis block.
        let ledger = CurrentLedger::load(genesis.clone(), StorageMode::Production).unwrap();
        // Ensure the genesis block is correct.
        assert_eq!(genesis, ledger.get_block(0).unwrap());
        // Return the ledger.
        ledger
    }

    #[test]
    fn test_foreign_record_spend() {
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let TestEnv { ledger, private_key, view_key, address, .. } =
            sample_test_env(rng);

        // A helper function to find records.
        let find_records = |records_view_key, records_private_key| {
            let microcredits = Identifier::from_str("microcredits").unwrap();
            ledger
                .find_records(&records_view_key, RecordsFilter::SlowUnspent(records_private_key))
                .unwrap()
                .filter(|(_, record)| match record.data().get(&microcredits) {
                    Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                    _ => false,
                })
                .collect::<indexmap::IndexMap<_, _>>()
        };

        // Sample a new account.
        let second_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let second_view_key = ViewKey::try_from(&second_private_key).unwrap();
        let second_address = Address::try_from(&second_private_key).unwrap();

        // Send transfer_public_to_private to the new account.
        {
            let inputs = [
                Value::from_str(&format!("{second_address}")).unwrap(),
                Value::from_str("1000000000000u64").unwrap(),
            ];
            let transaction = ledger
                .vm()
                .execute(&private_key, ("credits.aleo", "transfer_public_to_private"), inputs.iter(), None, 0, None, rng)
                .unwrap();
            let block = ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
            ledger.check_next_block(&block, rng).unwrap();
            ledger.advance_to_next_block(&block).unwrap();
        }

        // Fetch the unspent records for the first account.
        let records_first = find_records(view_key, private_key);
        let record_first_1 = records_first[0].clone();
        // Fetch the unspent records for the new account.
        let records_second = find_records(second_view_key, second_private_key);
        let record_second_1 = records_second[0].clone();

        // Define a program which takes as input two records and returns the sum of their balances.
        let program = Program::<CurrentNetwork>::from_str(
            r"
    import credits.aleo;

    program sum_balances.aleo;

    function sum_balances:
        input r0 as credits.aleo/credits.record;
        input r1 as credits.aleo/credits.record;

        add r0.microcredits r1.microcredits into r2;
        output r2 as u64.public;").unwrap();

        // Deploy the program.
        let deployment = ledger.vm().deploy(&private_key, &program, None, 0, None, rng).unwrap();
        // Print the deployment cost.
        println!("Deployment cost: {}", deployment.fee_amount().unwrap());
        let block = ledger
            .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment], rng)
            .unwrap();
        // Check that the block does not contain any rejected or aborted transactions.
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        ledger.check_next_block(&block, rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();

        // Execute `sum_balances` with records from two different accounts.
        println!("\n\n\n***************************\n\n");
        let inputs = [
            Value::Record(record_first_1.clone()),
            Value::Record(record_second_1.clone()),
        ];
        let transaction = ledger
            .vm()
            .execute(&private_key, ("sum_balances.aleo", "sum_balances"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        let block = ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
        // Check that the block does not contain any rejected or aborted transactions.
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        ledger.check_next_block(&block, rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();
    }

    fn create_example_circuit<E: Environment>() -> Field<E> {
        let one = snarkvm_console::types::Field::<E::Network>::one();
        let two = one + one;

        const REPETITIONS: u64 = 10;

        // Reminder: the proof system instantiates 3 more variables and constraints to make the proof hiding.
        let mut accumulator = Field::new(Mode::Public, two);
        for _ in 0..REPETITIONS {
            accumulator *= accumulator.clone();
        }

        // NOTE: using these functions leads to type issues some reason...
        // let final_value = accumulator.eject_value();
        // let final_value_circuit = Field::new(Mode::Public, final_value);
        // E::assert_eq(accumulator, final_value_circuit);
        // E::enforce(||(accumulator, accumulator, final_value_circuit));

        assert!(E::is_satisfied());

        accumulator
    }

    #[test]
    fn test_example_circuit() {
        let _candidate_output = create_example_circuit::<Circuit>();
        let assignment = Circuit::eject_assignment_and_reset();
        assert_eq!(0, Circuit::num_constants());
        assert_eq!(1, Circuit::num_public());
        assert_eq!(0, Circuit::num_private());
        assert_eq!(0, Circuit::num_constraints());

        // Varuna setup, prove, and verify.

        use snarkvm_algorithms::{
            crypto_hash::PoseidonSponge,
            snark::varuna::{VarunaHidingMode, VarunaSNARK, ahp::AHPForR1CS},
        };
        use snarkvm_circuit::Field;
        use snarkvm_curves::bls12_377::{Bls12_377, Fq};
        use snarkvm_utilities::rand::TestRng;

        type FS = PoseidonSponge<Fq, 2, 1>;
        type VarunaInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;

        let rng = &mut TestRng::default();

        let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(200, 200, 300).unwrap();
        let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
        let universal_prover = &universal_srs.to_universal_prover().unwrap();
        let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
        let fs_pp = FS::sample_parameters();

        let (index_pk, index_vk) = VarunaInst::circuit_setup(&universal_srs, &assignment).unwrap();
        println!("Called circuit setup");

        let proof = VarunaInst::prove(universal_prover, &fs_pp, &index_pk, &assignment, rng).unwrap();
        println!("Called prover");

        let one = <Circuit as Environment>::BaseField::one();
        assert!(VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, [one, one + one], &proof).unwrap());
        println!("Called verifier");
        println!("\nShould not verify (i.e. verifier messages should print below):");
        assert!(!VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, [one, one], &proof).unwrap());

        // Import an MPC proof and try again.
        // TODO: Marlin's Proof doesn't even have the same structure as Varuna's Proof.
        // use snarkvm_utilities::CanonicalDeserialize;
        // let file = std::fs::File::create("proof.bin").unwrap();
        // let mut reader = std::io::BufReader::new(file);
        // let proof = Proof::deserialize(&mut reader).unwrap();
        // assert!(VarunaInst::verify(universal_verifier, &fs_pp, &index_vk, [one, one + one], &proof).unwrap());
    }

    // #[test]
    // #[allow(clippy::needless_borrow)]
    // fn divide_polynomials_random() {
    //     let rng = &mut TestRng::default();

    //     for a_degree in 0..70 {
    //         for b_degree in 0..70 {

    //             let dividend = snarkvm_fft::DensePolynomial::<mpc_algebra::MpcField<Fr, mpc_algebra::SpdzFieldShare<Fr>>>::rand(a_degree, rng);
    //             let divisor = snarkvm_fft::DensePolynomial::<mpc_algebra::MpcField<Fr, mpc_algebra::SpdzFieldShare<Fr>>>::rand(b_degree, rng);
    //             let (quotient, remainder) =
    //                 snarkvm_fft::Polynomial::divide_with_q_and_r(&(&dividend).into(), &(&divisor).into()).unwrap();
    //             assert_eq!(dividend, &(&divisor * &quotient) + &remainder)
    //         }
    //     }
    // }
}

