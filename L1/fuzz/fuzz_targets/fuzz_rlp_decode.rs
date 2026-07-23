// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for the EVM RLP header decoder.
//!
//! `block_header_rlp` inside `ChainProof::Evm` comes from an external chain
//! and is fully attacker-influenced before Quantos validators verify it
//! (`src/l0/light_client.rs::verify_evm`). A malformed/truncated/adversarial
//! RLP encoding must be rejected with `Err`, never panic — this was a real
//! bug (out-of-bounds slice index) found and fixed as part of §14.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::l0::light_client::decode_rlp_list_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    let _ = decode_rlp_list_for_fuzzing(data);
});
