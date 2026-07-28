// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `CommitteeVote` deserialization.
//!
//! Committee votes are received via P2P and deserialized with
//! `bincode::deserialize::<CommitteeVote>` before
//! `FastPath::receive_vote` (`src/consensus/fast_path.rs`) processes them.
//! A Byzantine peer can send arbitrary bytes to this boundary.
//! Deserialization must never panic or cause unbounded resource usage.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::types::CommitteeVote;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<CommitteeVote>(data);
});
