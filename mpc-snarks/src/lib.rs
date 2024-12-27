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

    pub(crate) type CurrentLedger =
        Ledger<CurrentNetwork, memory::ConsensusMemory<CurrentNetwork>>;
    pub(crate) type CurrentConsensusStore =
        ConsensusStore<CurrentNetwork, memory::ConsensusMemory<CurrentNetwork>>;

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
}

