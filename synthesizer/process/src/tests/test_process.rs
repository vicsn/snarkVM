// Copyright 2024 Aleo Network Foundation
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

use console::{
    network::MainnetV0,
    prelude::Network,
    program::{Parser, ProgramID},
};
use synthesizer_program::Program;

use crate::Process;

type CurrentNetwork = MainnetV0;

#[test]
pub fn test_credits() {
    let process = Process::load_testing_only().unwrap();
    let credits_id = ProgramID::<CurrentNetwork>::from_str("credits.aleo").unwrap();
    assert!(process.contains_program(&credits_id));
}

#[test]
pub fn test_cache() {
    let (_, program1) = Program::<CurrentNetwork>::parse(
        r"
program testing1.aleo;

function compute:
    input r0 as u32.private;
    input r1 as u32.public;
    add r0 r1 into r2;
    output r2 as u32.public;",
    )
    .unwrap();
    // Initialize a new process.
    let process = crate::test_helpers::sample_process(&program1);
    // Check whether the program is in memory.
    assert_eq!(process.num_stacks_in_memory(), 1);
    assert!(process.contains_program_in_memory(program1.id()));
}

#[test]
pub fn test_cache_evict() {
    // Prepare the credit program id.
    let credits_id = ProgramID::<CurrentNetwork>::from_str("credits.aleo").unwrap();
    // Create a program sampler which imports credits.aleo.
    let mid_program_template = |i| {
        format!(
            r"
import credits.aleo;

program mid{i}.aleo;

function mid{i}_transfer:
    input r0 as credits.aleo/credits.record;
    input r1 as address.private;
    input r2 as u64.private;

    call credits.aleo/transfer_private r0 r1 r2 into r3 r4;

    output r3 as credits.aleo/credits.record;
    output r4 as credits.aleo/credits.record;"
        )
    };
    // Create a program sampler which imports mid1.aleo and mid2.aleo.
    let root_program_template = |i| {
        format!(
            r"
import credits.aleo;
import mid1.aleo;
import mid2.aleo;

program root{i}.aleo;

function root_call:
    input r0 as credits.aleo/credits.record;
    input r1 as address.private;
    input r2 as u64.private;

    // Call mid1's transfer function
    call mid1.aleo/mid1_transfer r0 r1 r2 into r3 r4;

    // Call mid2's transfer function
    call mid2.aleo/mid2_transfer r4 r1 r2 into r5 r6;

    output r3 as credits.aleo/credits.record;
    output r4 as credits.aleo/credits.record;
    output r5 as credits.aleo/credits.record;
    output r6 as credits.aleo/credits.record;"
        )
    };

    // Sample two programs.
    let (_, mid1) = Program::<CurrentNetwork>::parse(&mid_program_template(1)).unwrap();
    let (_, mid2) = Program::<CurrentNetwork>::parse(&mid_program_template(2)).unwrap();
    // Initialize a new process.
    let mut process = crate::test_helpers::sample_process(&mid1);

    // Adding the root program should fail because an import is missing from memory and storage.
    let (_, root1) = Program::<CurrentNetwork>::parse(&root_program_template(1)).unwrap();
    assert!(process.add_program(&root1).is_err());
    assert!(!process.contains_program_in_memory(root1.id()));

    // Check whether mid1 is in memory.
    assert!(process.contains_program_in_memory(mid1.id()));
    assert_eq!(process.num_stacks_in_memory(), 1);
    // add mid2 to memory
    process.add_program(&mid2).unwrap();
    // Check whether mid2 is in memory.
    assert!(process.contains_program_in_memory(mid2.id()));
    assert_eq!(process.num_stacks_in_memory(), 2);

    for i in 3..=<CurrentNetwork as Network>::MAX_STACKS + 1 {
        let (_, program) = Program::<CurrentNetwork>::parse(&root_program_template(i)).unwrap();
        process.add_program(&program).unwrap();
        // The new program and imports should be cached.
        assert!(process.contains_program_in_memory(program.id()));
        assert!(process.contains_program_in_memory(mid1.id()));
        assert!(process.contains_program_in_memory(mid2.id()));
    }

    // Only MAX_STACKS programs are cached, so the oldest root should be evicted.
    let root3_id = ProgramID::<CurrentNetwork>::from_str("root3.aleo").unwrap();
    assert!(!process.contains_program_in_memory(&root3_id));
    // Test we still have credits.aleo in memory.
    assert!(process.contains_program_in_memory(&credits_id));
    // Test that an example root program's imports are correct.
    let root4_id = ProgramID::<CurrentNetwork>::from_str("root4.aleo").unwrap();
    let root4_stack = process.get_stack(root4_id).unwrap();
    let root4_import_ids = root4_stack.all_external_stacks().into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    let expected_imports = vec![credits_id, credits_id, *mid1.id(), credits_id, *mid2.id()];
    assert_eq!(root4_import_ids, expected_imports);
}

#[test]
pub fn test_real_example_cache_evict() {
    // Prepare programs.
    let prelim_program_1 = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;

program staking_v1.aleo;

record PrivateToken:
    owner as address.private;
    amount as u64.private;

struct Metadata:
    name as u128;
    symbol as u128;
    decimals as u8;

struct State:
    total_supply as u64;
    total_reserve as u64;
    total_unstaking as u64;
    total_reward as u64;

struct Settings:
    unstake_wait as u32;
    stake_paused as boolean;
    global_paused as boolean;
    max_reward_per_notify as u64;
    protocol_fee as u16;
    fee_account as address;

struct Unstaking:
    microcredits as u64;
    height as u32;

struct ApprovalKey:
    approver as address;
    spender as address;

mapping account:
    key as address.public;
    value as u64.public;

mapping approvals:
    key as field.public;
    value as u64.public;

mapping metadata:
    key as boolean.public;
    value as Metadata.public;

mapping state:
    key as boolean.public;
    value as State.public;

mapping settings:
    key as boolean.public;
    value as Settings.public;

mapping unstakings:
    key as address.public;
    value as Unstaking.public;

mapping admins:
    key as address.public;
    value as boolean.public;

mapping stakers:
    key as address.public;
    value as boolean.public;

function transfer_public:
    input r0 as address.public;
    input r1 as u64.public;
    async transfer_public self.caller r0 r1 into r2;
    output r2 as staking_v1.aleo/transfer_public.future;
finalize transfer_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    get account[r0] into r3;
    sub r3 r2 into r4;
    set r4 into account[r0];
    get.or_use account[r1] 0u64 into r5;
    add r5 r2 into r6;
    set r6 into account[r1];

function transfer_private:
    input r0 as PrivateToken.record;
    input r1 as address.private;
    input r2 as u64.private;
    cast r1 r2 into r3 as PrivateToken.record;
    sub r0.amount r2 into r4;
    cast r0.owner r4 into r5 as PrivateToken.record;
    output r3 as PrivateToken.record;
    output r5 as PrivateToken.record;

function transfer_private_to_public:
    input r0 as PrivateToken.record;
    input r1 as address.public;
    input r2 as u64.public;
    sub r0.amount r2 into r3;
    cast r0.owner r3 into r4 as PrivateToken.record;
    async transfer_private_to_public r1 r2 into r5;
    output r4 as PrivateToken.record;
    output r5 as staking_v1.aleo/transfer_private_to_public.future;
finalize transfer_private_to_public:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];

function transfer_public_to_private:
    input r0 as address.private;
    input r1 as u64.public;
    cast r0 r1 into r2 as PrivateToken.record;
    async transfer_public_to_private self.caller r1 into r3;
    output r2 as PrivateToken.record;
    output r3 as staking_v1.aleo/transfer_public_to_private.future;
finalize transfer_public_to_private:
    input r0 as address.public;
    input r1 as u64.public;
    get account[r0] into r2;
    sub r2 r1 into r3;
    set r3 into account[r0];

function join:
    input r0 as PrivateToken.record;
    input r1 as PrivateToken.record;
    add r0.amount r1.amount into r2;
    cast r0.owner r2 into r3 as PrivateToken.record;
    output r3 as PrivateToken.record;

function stake_public:
    input r0 as u64.public;
    input r1 as address.public;
    assert.neq r0 0u64;
    call credits.aleo/transfer_public_as_signer staking_v1.aleo r0 into r2;
    async stake_public r0 r1 r2 into r3;
    output r3 as staking_v1.aleo/stake_public.future;
finalize stake_public:
    input r0 as u64.public;
    input r1 as address.public;
    input r2 as credits.aleo/transfer_public_as_signer.future;
    await r2;
    get settings[true] into r3;
    assert.eq r3.stake_paused false;
    assert.eq r3.global_paused false;
    get state[true] into r4;
    is.eq r4.total_reserve 0u64 into r5;
    cast r4.total_reserve into r6 as u128;
    ternary r5 1u128 r6 into r7;
    is.eq r4.total_reserve 0u64 into r8;
    cast r0 into r9 as u128;
    cast r4.total_supply into r10 as u128;
    mul r9 r10 into r11;
    div r11 r7 into r12;
    cast r12 into r13 as u64;
    ternary r8 r0 r13 into r14;
    assert.neq r14 0u64;
    add r4.total_supply r14 into r15;
    add r4.total_reserve r0 into r16;
    cast r15 r16 r4.total_unstaking r4.total_reward into r17 as State;
    set r17 into state[true];
    get.or_use account[r1] 0u64 into r18;
    add r18 r14 into r19;
    set r19 into account[r1];

function stake_private:
    input r0 as credits.aleo/credits.record;
    input r1 as u64.public;
    input r2 as address.public;
    assert.neq r1 0u64;
    call credits.aleo/transfer_private_to_public r0 staking_v1.aleo r1 into r3 r4;
    async stake_private r1 r2 r4 into r5;
    output r3 as credits.aleo/credits.record;
    output r5 as staking_v1.aleo/stake_private.future;
finalize stake_private:
    input r0 as u64.public;
    input r1 as address.public;
    input r2 as credits.aleo/transfer_private_to_public.future;
    await r2;
    get settings[true] into r3;
    assert.eq r3.stake_paused false;
    assert.eq r3.global_paused false;
    get state[true] into r4;
    is.eq r4.total_reserve 0u64 into r5;
    cast r4.total_reserve into r6 as u128;
    ternary r5 1u128 r6 into r7;
    is.eq r4.total_reserve 0u64 into r8;
    cast r0 into r9 as u128;
    cast r4.total_supply into r10 as u128;
    mul r9 r10 into r11;
    div r11 r7 into r12;
    cast r12 into r13 as u64;
    ternary r8 r0 r13 into r14;
    assert.neq r14 0u64;
    add r4.total_supply r14 into r15;
    add r4.total_reserve r0 into r16;
    cast r15 r16 r4.total_unstaking r4.total_reward into r17 as State;
    set r17 into state[true];
    get.or_use account[r1] 0u64 into r18;
    add r18 r14 into r19;
    set r19 into account[r1];

function unstake_token:
    input r0 as u64.public;
    assert.neq r0 0u64;
    async unstake_token self.caller r0 into r1;
    output r1 as staking_v1.aleo/unstake_token.future;
finalize unstake_token:
    input r0 as address.public;
    input r1 as u64.public;
    get settings[true] into r2;
    assert.eq r2.global_paused false;
    get.or_use account[r0] 0u64 into r3;
    sub r3 r1 into r4;
    set r4 into account[r0];
    get state[true] into r5;
    cast r1 into r6 as u128;
    cast r5.total_reserve into r7 as u128;
    mul r6 r7 into r8;
    cast r5.total_supply into r9 as u128;
    div r8 r9 into r10;
    cast r10 into r11 as u64;
    assert.neq r11 0u64;
    sub r5.total_supply r1 into r12;
    sub r5.total_reserve r11 into r13;
    add r5.total_unstaking r11 into r14;
    cast r12 r13 r14 r5.total_reward into r15 as State;
    set r15 into state[true];
    cast 0u64 0u32 into r16 as Unstaking;
    get.or_use unstakings[r0] r16 into r17;
    add r17.microcredits r11 into r18;
    add block.height r2.unstake_wait into r19;
    cast r18 r19 into r20 as Unstaking;
    set r20 into unstakings[r0];

function unstake_aleo:
    input r0 as u64.public;
    assert.neq r0 0u64;
    async unstake_aleo self.caller r0 into r1;
    output r1 as staking_v1.aleo/unstake_aleo.future;
finalize unstake_aleo:
    input r0 as address.public;
    input r1 as u64.public;
    get settings[true] into r2;
    assert.eq r2.global_paused false;
    get state[true] into r3;
    cast r1 into r4 as u128;
    cast r3.total_supply into r5 as u128;
    mul r4 r5 into r6;
    cast r3.total_reserve into r7 as u128;
    add r6 r7 into r8;
    sub r8 1u128 into r9;
    cast r3.total_reserve into r10 as u128;
    div r9 r10 into r11;
    cast r11 into r12 as u64;
    assert.neq r12 0u64;
    get.or_use account[r0] 0u64 into r13;
    sub r13 r12 into r14;
    set r14 into account[r0];
    sub r3.total_supply r12 into r15;
    sub r3.total_reserve r1 into r16;
    add r3.total_unstaking r1 into r17;
    cast r15 r16 r17 r3.total_reward into r18 as State;
    set r18 into state[true];
    cast 0u64 0u32 into r19 as Unstaking;
    get.or_use unstakings[r0] r19 into r20;
    add r20.microcredits r1 into r21;
    add block.height r2.unstake_wait into r22;
    cast r21 r22 into r23 as Unstaking;
    set r23 into unstakings[r0];

function withdraw:
    input r0 as u64.public;
    input r1 as address.public;
    assert.neq r0 0u64;
    call credits.aleo/transfer_public r1 r0 into r2;
    async withdraw self.caller r0 r2 into r3;
    output r3 as staking_v1.aleo/withdraw.future;
finalize withdraw:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as credits.aleo/transfer_public.future;
    await r2;
    get settings[true] into r3;
    assert.eq r3.global_paused false;
    get unstakings[r0] into r4;
    gte block.height r4.height into r5;
    assert.eq r5 true;
    sub r4.microcredits r1 into r6;
    cast r6 r4.height into r7 as Unstaking;
    set r7 into unstakings[r0];
    get state[true] into r8;
    sub r8.total_unstaking r1 into r9;
    cast r8.total_supply r8.total_reserve r9 r8.total_reward into r10 as State;
    set r10 into state[true];

function withdraw_private:
    input r0 as u64.public;
    input r1 as address.private;
    assert.neq r0 0u64;
    call credits.aleo/transfer_public_to_private r1 r0 into r2 r3;
    async withdraw_private self.caller r0 r3 into r4;
    output r2 as credits.aleo/credits.record;
    output r4 as staking_v1.aleo/withdraw_private.future;
finalize withdraw_private:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as credits.aleo/transfer_public_to_private.future;
    await r2;
    get settings[true] into r3;
    assert.eq r3.global_paused false;
    get unstakings[r0] into r4;
    gte block.height r4.height into r5;
    assert.eq r5 true;
    sub r4.microcredits r1 into r6;
    cast r6 r4.height into r7 as Unstaking;
    set r7 into unstakings[r0];
    get state[true] into r8;
    sub r8.total_unstaking r1 into r9;
    cast r8.total_supply r8.total_reserve r9 r8.total_reward into r10 as State;
    set r10 into state[true];

function approve_public:
    input r0 as address.public;
    input r1 as u64.public;
    cast self.caller r0 into r2 as ApprovalKey;
    hash.bhp256 r2 into r3 as field;
    async approve_public r3 r1 into r4;
    output r4 as staking_v1.aleo/approve_public.future;
finalize approve_public:
    input r0 as field.public;
    input r1 as u64.public;
    get.or_use approvals[r0] 0u64 into r2;
    sub 18446744073709551615u64 r2 into r3;
    lt r1 r3 into r4;
    add.w r2 r1 into r5;
    ternary r4 r5 18446744073709551615u64 into r6;
    set r6 into approvals[r0];

function unapprove_public:
    input r0 as address.public;
    input r1 as u64.public;
    cast self.caller r0 into r2 as ApprovalKey;
    hash.bhp256 r2 into r3 as field;
    async unapprove_public r3 r1 into r4;
    output r4 as staking_v1.aleo/unapprove_public.future;
finalize unapprove_public:
    input r0 as field.public;
    input r1 as u64.public;
    get approvals[r0] into r2;
    gt r2 r1 into r3;
    sub.w r2 r1 into r4;
    ternary r3 r4 0u64 into r5;
    set r5 into approvals[r0];

function transfer_from_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    cast r0 self.caller into r3 as ApprovalKey;
    hash.bhp256 r3 into r4 as field;
    async transfer_from_public r4 r0 r1 r2 into r5;
    output r5 as staking_v1.aleo/transfer_from_public.future;
finalize transfer_from_public:
    input r0 as field.public;
    input r1 as address.public;
    input r2 as address.public;
    input r3 as u64.public;
    get approvals[r0] into r4;
    sub r4 r3 into r5;
    set r5 into approvals[r0];
    get account[r1] into r6;
    sub r6 r3 into r7;
    set r7 into account[r1];
    get.or_use account[r2] 0u64 into r8;
    add r8 r3 into r9;
    set r9 into account[r2];

function notify_reward:
    input r0 as u64.public;
    assert.neq r0 0u64;
    async notify_reward self.caller r0 into r1;
    output r1 as staking_v1.aleo/notify_reward.future;
finalize notify_reward:
    input r0 as address.public;
    input r1 as u64.public;
    get settings[true] into r2;
    assert.eq r2.global_paused false;
    get stakers[r0] into r3;
    assert.eq r3 true;
    lte r1 r2.max_reward_per_notify into r4;
    assert.eq r4 true;
    get state[true] into r5;
    cast r5.total_reserve into r6 as u128;
    mul r6 10000u128 into r7;
    cast r1 into r8 as u128;
    cast r2.protocol_fee into r9 as u128;
    sub 10000u128 r9 into r10;
    mul r8 r10 into r11;
    add r7 r11 into r12;
    cast r2.protocol_fee into r13 as u128;
    cast r1 into r14 as u128;
    mul r13 r14 into r15;
    cast r5.total_supply into r16 as u128;
    mul r15 r16 into r17;
    div r17 r12 into r18;
    cast r18 into r19 as u64;
    add r5.total_supply r19 into r20;
    add r5.total_reserve r1 into r21;
    add r5.total_reward r1 into r22;
    cast r20 r21 r5.total_unstaking r22 into r23 as State;
    set r23 into state[true];
    get.or_use account[r2.fee_account] 0u64 into r24;
    add r24 r19 into r25;
    set r25 into account[r2.fee_account];

function pull_aleo:
    input r0 as u64.public;
    call credits.aleo/transfer_public self.caller r0 into r1;
    async pull_aleo self.caller r1 into r2;
    output r2 as staking_v1.aleo/pull_aleo.future;
finalize pull_aleo:
    input r0 as address.public;
    input r1 as credits.aleo/transfer_public.future;
    await r1;
    get settings[true] into r2;
    assert.eq r2.global_paused false;
    get stakers[r0] into r3;
    assert.eq r3 true;

function update_settings:
    input r0 as Settings.public;
    lte r0.protocol_fee 5000u16 into r1;
    assert.eq r1 true;
    async update_settings self.caller r0 into r2;
    output r2 as staking_v1.aleo/update_settings.future;
finalize update_settings:
    input r0 as address.public;
    input r1 as Settings.public;
    get admins[r0] into r2;
    assert.eq r2 true;
    set r1 into settings[true];

function set_staker:
    input r0 as address.public;
    input r1 as boolean.public;
    async set_staker self.caller r0 r1 into r2;
    output r2 as staking_v1.aleo/set_staker.future;
finalize set_staker:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as boolean.public;
    get admins[r0] into r3;
    assert.eq r3 true;
    set r2 into stakers[r1];

function set_admin:
    input r0 as address.public;
    input r1 as boolean.public;
    assert.neq self.caller r0;
    async set_admin self.caller r0 r1 into r2;
    output r2 as staking_v1.aleo/set_admin.future;
finalize set_admin:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as boolean.public;
    get admins[r0] into r3;
    assert.eq r3 true;
    set r2 into admins[r1];

function init:
    input r0 as address.public;
    assert.eq self.caller aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj;
    async init r0 into r1;
    output r1 as staking_v1.aleo/init.future;
finalize init:
    input r0 as address.public;
    contains metadata[true] into r1;
    assert.eq r1 false;
    cast 394103260206656316532079u128 126943148918095u128 6u8 into r2 as Metadata;
    set r2 into metadata[true];
    set true into admins[aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj];
    cast 0u64 0u64 0u64 0u64 into r3 as State;
    set r3 into state[true];
    cast 360u32 false false 1000000000u64 1000u16 r0 into r4 as Settings;
    set r4 into settings[true];
    ",
    )
    .unwrap();
    // Prepare second program.
    let prelim_program_2 = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
import staking_v1.aleo;

program staker_v1_b.aleo;

struct bond_state:
    validator as address;
    microcredits as u64;

struct unbond_state:
    microcredits as u64;
    height as u32;

struct Settings:
    unstake_wait as u32;
    stake_paused as boolean;
    global_paused as boolean;
    max_reward_per_notify as u64;
    protocol_fee as u16;
    fee_account as address;

struct StakerState:
    total_pulled as u64;
    total_pushed as u64;
    total_reward as u64;

mapping admins:
    key as address.public;
    value as boolean.public;

mapping operators:
    key as address.public;
    value as boolean.public;

mapping state:
    key as boolean.public;
    value as StakerState.public;

function notify_reward:
    input r0 as u64.public;
    call staking_v1.aleo/notify_reward r0 into r1;
    async notify_reward self.caller r0 r1 into r2;
    output r2 as staker_v1_b.aleo/notify_reward.future;
finalize notify_reward:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as staking_v1.aleo/notify_reward.future;
    await r2;
    get operators[r0] into r3;
    assert.eq r3 true;
    get.or_use credits.aleo/account[staker_v1_b.aleo] 0u64 into r4;
    cast aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc 0u64 into r5 as bond_state;
    get.or_use credits.aleo/bonded[staker_v1_b.aleo] r5 into r6;
    cast 0u64 0u32 into r7 as unbond_state;
    get.or_use credits.aleo/unbonding[staker_v1_b.aleo] r7 into r8;
    get state[true] into r9;
    add r4 r6.microcredits into r10;
    add r10 r8.microcredits into r11;
    add r11 r9.total_pushed into r12;
    sub r12 r9.total_pulled into r13;
    sub r13 r9.total_reward into r14;
    lte r1 r14 into r15;
    assert.eq r15 true;
    add r9.total_reward r1 into r16;
    cast r9.total_pulled r9.total_pushed r16 into r17 as StakerState;
    set r17 into state[true];

function set_admin:
    input r0 as address.public;
    input r1 as boolean.public;
    assert.neq self.caller r0;
    async set_admin self.caller r0 r1 into r2;
    output r2 as staker_v1_b.aleo/set_admin.future;
finalize set_admin:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as boolean.public;
    get admins[r0] into r3;
    assert.eq r3 true;
    set r2 into admins[r1];

function init:
    assert.eq self.caller aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj;
    async init  into r0;
    output r0 as staker_v1_b.aleo/init.future;
finalize init:
    contains admins[aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj] into r0;
    assert.eq r0 false;
    set true into admins[aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj];
    set true into operators[aleo18jfrqsz4m853grpgzflrlzdkcm9art926668g80vd9ruyzv8rsqqlchzyj];
    cast 0u64 0u64 0u64 into r1 as StakerState;
    set r1 into state[true];

function bond:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    lte r2 r1 into r3;
    assert.eq r3 true;
    call staking_v1.aleo/pull_aleo r2 into r4;
    call credits.aleo/bond_public r0 staker_v1_b.aleo r1 into r5;
    async bond self.caller r2 r4 r5 into r6;
    output r6 as staker_v1_b.aleo/bond.future;
finalize bond:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as staking_v1.aleo/pull_aleo.future;
    input r3 as credits.aleo/bond_public.future;
    await r2;
    await r3;
    get operators[r0] into r4;
    assert.eq r4 true;
    get state[true] into r5;
    add r5.total_pulled r1 into r6;
    cast r6 r5.total_pushed r5.total_reward into r7 as StakerState;
    set r7 into state[true];

function unbond:
    input r0 as u64.public;
    assert.neq r0 0u64;
    call credits.aleo/unbond_public staker_v1_b.aleo r0 into r1;
    async unbond self.caller r1 into r2;
    output r2 as staker_v1_b.aleo/unbond.future;
finalize unbond:
    input r0 as address.public;
    input r1 as credits.aleo/unbond_public.future;
    await r1;
    get operators[r0] into r2;
    assert.eq r2 true;

function claim:
    call credits.aleo/claim_unbond_public staker_v1_b.aleo into r0;
    async claim self.caller r0 into r1;
    output r1 as staker_v1_b.aleo/claim.future;
finalize claim:
    input r0 as address.public;
    input r1 as credits.aleo/claim_unbond_public.future;
    await r1;
    get operators[r0] into r2;
    assert.eq r2 true;

function push_aleo:
    input r0 as u64.public;
    assert.neq r0 0u64;
    call credits.aleo/transfer_public staking_v1.aleo r0 into r1;
    async push_aleo self.caller r0 r1 into r2;
    output r2 as staker_v1_b.aleo/push_aleo.future;
finalize push_aleo:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as credits.aleo/transfer_public.future;
    await r2;
    get operators[r0] into r3;
    assert.eq r3 true;
    get state[true] into r4;
    add r4.total_pushed r1 into r5;
    cast r4.total_pulled r5 r4.total_reward into r6 as StakerState;
    set r6 into state[true];

function claim_and_push:
    input r0 as u64.public;
    call credits.aleo/claim_unbond_public staker_v1_b.aleo into r1;
    call credits.aleo/transfer_public staking_v1.aleo r0 into r2;
    async claim_and_push self.caller r0 r1 r2 into r3;
    output r3 as staker_v1_b.aleo/claim_and_push.future;
finalize claim_and_push:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as credits.aleo/claim_unbond_public.future;
    input r3 as credits.aleo/transfer_public.future;
    await r2;
    await r3;
    get operators[r0] into r4;
    assert.eq r4 true;
    get state[true] into r5;
    add r5.total_pushed r1 into r6;
    cast r5.total_pulled r6 r5.total_reward into r7 as StakerState;
    set r7 into state[true];

function set_operator:
    input r0 as address.public;
    input r1 as boolean.public;
    async set_operator self.caller r0 r1 into r2;
    output r2 as staker_v1_b.aleo/set_operator.future;
finalize set_operator:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as boolean.public;
    get admins[r0] into r3;
    assert.eq r3 true;
    set r2 into operators[r1];
        ",
    )
    .unwrap();

    let prelim_program_3 = Program::<CurrentNetwork>::from_str(
        r"
program multisig_v1.aleo;

struct Operation:
    program_id as address;
    op_type as u8;
    params as field;
    op_salt as u64;
    delay as u32;

struct Request:
    operation as Operation;
    multisig as address;

struct ReqState:
    state as u8;
    active_block as u32;

mapping admins:
    key as address.public;
    value as boolean.public;

mapping initialized:
    key as u8.public;
    value as boolean.public;

mapping requests:
    key as field.public;
    value as ReqState.public;

function init:
    input r0 as [address; 5u32].public;
    assert.neq r0[0u32] aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    assert.neq r0[1u32] aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    assert.neq r0[2u32] aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    assert.neq r0[3u32] aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    assert.neq r0[4u32] aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    assert.neq r0[0u32] r0[1u32];
    assert.neq r0[0u32] r0[2u32];
    assert.neq r0[0u32] r0[3u32];
    assert.neq r0[0u32] r0[4u32];
    assert.neq r0[1u32] r0[2u32];
    assert.neq r0[1u32] r0[3u32];
    assert.neq r0[1u32] r0[4u32];
    assert.neq r0[2u32] r0[3u32];
    assert.neq r0[2u32] r0[4u32];
    assert.neq r0[3u32] r0[4u32];
    async init r0 into r1;
    output r1 as multisig_v1.aleo/init.future;
finalize init:
    input r0 as [address; 5u32].public;
    contains initialized[1u8] into r1;
    assert.eq r1 false;
    set true into initialized[1u8];
    set true into admins[r0[0u32]];
    set true into admins[r0[1u32]];
    set true into admins[r0[2u32]];
    set true into admins[r0[3u32]];
    set true into admins[r0[4u32]];

closure verify_signatures:
    input r0 as Request;
    input r1 as [address; 3u32];
    input r2 as [signature; 3u32];
    assert.neq r1[0u32] r1[1u32];
    assert.neq r1[0u32] r1[2u32];
    assert.neq r1[1u32] r1[2u32];
    hash.bhp256 r0 into r3 as field;
    sign.verify r2[0u32] r1[0u32] r3 into r4;
    assert.eq r4 true;
    sign.verify r2[1u32] r1[1u32] r3 into r5;
    assert.eq r5 true;
    sign.verify r2[2u32] r1[2u32] r3 into r6;
    assert.eq r6 true;
    output r3 as field;

function change_admin:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.private;
    input r3 as [address; 3u32].public;
    input r4 as [signature; 3u32].private;
    assert.neq r0 r1;
    assert.neq r1 aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc;
    cast r0 r1 into r5 as [address; 2u32];
    hash.bhp256 r5 into r6 as field;
    cast multisig_v1.aleo 1u8 r6 r2 0u32 into r7 as Operation;
    cast r7 multisig_v1.aleo into r8 as Request;
    call verify_signatures r8 r3 r4 into r9;
    async change_admin r0 r1 r9 r3 into r10;
    output r10 as multisig_v1.aleo/change_admin.future;
finalize change_admin:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as field.public;
    input r3 as [address; 3u32].public;
    get admins[r3[0u32]] into r4;
    assert.eq r4 true;
    get admins[r3[1u32]] into r5;
    assert.eq r5 true;
    get admins[r3[2u32]] into r6;
    assert.eq r6 true;
    contains requests[r2] into r7;
    assert.eq r7 false;
    cast 1u8 block.height into r8 as ReqState;
    set r8 into requests[r2];
    get admins[r0] into r9;
    assert.eq r9 true;
    get.or_use admins[r1] false into r10;
    assert.eq r10 false;
    remove admins[r0];
    set true into admins[r1];

function new_request:
    input r0 as Operation.public;
    input r1 as boolean.public;
    input r2 as [address; 3u32].public;
    input r3 as [signature; 3u32].private;
    cast r0 multisig_v1.aleo into r4 as Request;
    call verify_signatures r4 r2 r3 into r5;
    not r1 into r6;
    is.eq r0.program_id self.caller into r7;
    or r6 r7 into r8;
    assert.eq r8 true;
    not r1 into r9;
    is.eq r0.delay 0u32 into r10;
    or r9 r10 into r11;
    assert.eq r11 true;
    async new_request r1 r0.delay r5 r2 into r12;
    output r12 as multisig_v1.aleo/new_request.future;
finalize new_request:
    input r0 as boolean.public;
    input r1 as u32.public;
    input r2 as field.public;
    input r3 as [address; 3u32].public;
    get admins[r3[0u32]] into r4;
    assert.eq r4 true;
    get admins[r3[1u32]] into r5;
    assert.eq r5 true;
    get admins[r3[2u32]] into r6;
    assert.eq r6 true;
    contains requests[r2] into r7;
    assert.eq r7 false;
    ternary r0 1u8 0u8 into r8;
    add block.height r1 into r9;
    cast r8 r9 into r10 as ReqState;
    set r10 into requests[r2];

function cancel_request:
    input r0 as field.public;
    input r1 as [address; 3u32].public;
    input r2 as [signature; 3u32].private;
    cast multisig_v1.aleo 2u8 r0 0u64 0u32 into r3 as Operation;
    cast r3 multisig_v1.aleo into r4 as Request;
    call verify_signatures r4 r1 r2 into r5;
    async cancel_request r0 r1 into r6;
    output r6 as multisig_v1.aleo/cancel_request.future;
finalize cancel_request:
    input r0 as field.public;
    input r1 as [address; 3u32].public;
    get admins[r1[0u32]] into r2;
    assert.eq r2 true;
    get admins[r1[1u32]] into r3;
    assert.eq r3 true;
    get admins[r1[2u32]] into r4;
    assert.eq r4 true;
    get requests[r0] into r5;
    assert.eq r5.state 0u8;
    cast 2u8 r5.active_block into r6 as ReqState;
    set r6 into requests[r0];

function execute:
    input r0 as Operation.public;
    assert.eq r0.program_id self.caller;
    cast r0 multisig_v1.aleo into r1 as Request;
    hash.bhp256 r1 into r2 as field;
    async execute r2 into r3;
    output r3 as multisig_v1.aleo/execute.future;
finalize execute:
    input r0 as field.public;
    get requests[r0] into r1;
    assert.eq r1.state 0u8;
    lte r1.active_block block.height into r2;
    assert.eq r2 true;
    cast 1u8 r1.active_block into r3 as ReqState;
    set r3 into requests[r0];
    ",
    )
    .unwrap();

    let program_i = |i| {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
    import credits.aleo;
    import staking_v1.aleo;
    import staker_v1_b.aleo;
    import multisig_v1.aleo;

    program staker_v{i}_multisig_b.aleo;

    struct Settings:
        unstake_wait as u32;
        stake_paused as boolean;
        global_paused as boolean;
        max_reward_per_notify as u64;
        protocol_fee as u16;
        fee_account as address;
        fixed_stakers as boolean;

    struct Operation:
        program_id as address;
        op_type as u8;
        params as field;
        op_salt as u64;
        delay as u32;

    struct Request:
        operation as Operation;
        multisig as address;

    struct SetOperatorParams:
        operator as address;
        flag as boolean;

    function dummy:

    function set_operator:
        input r0 as address.public;
        input r1 as boolean.public;
        input r2 as u64.public;
        input r3 as [address; 3u32].public;
        input r4 as [signature; 3u32].private;
        cast r0 r1 into r5 as SetOperatorParams;
        hash.bhp256 r5 into r6 as field;
        cast staker_v1_multisig_b.aleo 3u8 r6 r2 0u32 into r7 as Operation;
        call multisig_v1.aleo/new_request r7 true r3 r4 into r8;
        call staker_v1_b.aleo/set_operator r0 r1 into r9;
        async set_operator r8 r9 into r10;
        output r10 as staker_v1_multisig_b.aleo/set_operator.future;

    finalize set_operator:
        input r0 as multisig_v1.aleo/new_request.future;
        input r1 as staker_v1_b.aleo/set_operator.future;
        await r0;
        await r1;

    function add_admin:
        input r0 as address.public;
        input r1 as u64.public;
        hash.bhp256 r0 into r2 as field;
        cast staker_v1_multisig_b.aleo 1u8 r2 r1 1200u32 into r3 as Operation;
        call multisig_v1.aleo/execute r3 into r4;
        call staker_v1_b.aleo/set_admin r0 true into r5;
        async add_admin r4 r5 into r6;
        output r6 as staker_v1_multisig_b.aleo/add_admin.future;

    finalize add_admin:
        input r0 as multisig_v1.aleo/execute.future;
        input r1 as staker_v1_b.aleo/set_admin.future;
        await r0;
        await r1;

    function remove_admin:
        input r0 as address.public;
        input r1 as u64.public;
        input r2 as [address; 3u32].public;
        input r3 as [signature; 3u32].private;
        assert.neq self.caller r0 ;
        hash.bhp256 r0 into r4 as field;
        cast staker_v1_multisig_b.aleo 2u8 r4 r1 0u32 into r5 as Operation;
        call multisig_v1.aleo/new_request r5 true r2 r3 into r6;
        call staker_v1_b.aleo/set_admin r0 false into r7;
        async remove_admin r6 r7 into r8;
        output r8 as staker_v1_multisig_b.aleo/remove_admin.future;

    finalize remove_admin:
        input r0 as multisig_v1.aleo/new_request.future;
        input r1 as staker_v1_b.aleo/set_admin.future;
        await r0;
        await r1;
            "
        ))
        .unwrap()
    };

    // Initialize a new process with the first preliminary program.
    let mut process = crate::test_helpers::sample_process(&prelim_program_1);
    assert_eq!(process.num_stacks_in_memory(), 1);
    assert!(process.contains_program_in_memory(prelim_program_1.id()));
    // Add the second preliminary program to the process.
    process.add_program(&prelim_program_2).unwrap();
    assert_eq!(process.num_stacks_in_memory(), 2);
    assert!(process.contains_program_in_memory(prelim_program_2.id()));
    // Add the third preliminary program to the process.
    process.add_program(&prelim_program_3).unwrap();
    assert_eq!(process.num_stacks_in_memory(), 3);
    assert!(process.contains_program_in_memory(prelim_program_3.id()));

    // Deploy MAX_STACKS dummy deployments to test cache eviction.
    for i in 0..=<CurrentNetwork as Network>::MAX_STACKS {
        let program = Program::<CurrentNetwork>::from_str(&format!(
            r"
program testing{i}.aleo;

function compute:"
        ))
        .unwrap();
        process.add_program(&program).unwrap();
        assert_eq!(process.num_stacks_in_memory(), (3 + 1 + i).min(CurrentNetwork::MAX_STACKS));
        assert!(process.contains_program_in_memory(program.id()));
    }

    // Add the first root program to the process.
    let root_1 = program_i(1);
    process.add_program(&root_1).unwrap();
    assert_eq!(process.num_stacks_in_memory(), CurrentNetwork::MAX_STACKS);
    assert!(process.contains_program_in_memory(root_1.id()));

    // Add 10 more dummy programs.
    for i in 0..10 {
        let program = Program::<CurrentNetwork>::from_str(&format!(
            r"
program testing_again{i}.aleo;

function compute:"
        ))
        .unwrap();
        process.add_program(&program).unwrap();
        assert_eq!(process.num_stacks_in_memory(), CurrentNetwork::MAX_STACKS);
        assert!(process.contains_program_in_memory(program.id()));
    }

    // Add the second root program to the process.
    let root_2 = program_i(2);
    process.add_program(&root_2).unwrap();
    assert_eq!(process.num_stacks_in_memory(), CurrentNetwork::MAX_STACKS);
    assert!(process.contains_program_in_memory(root_2.id()));
}
