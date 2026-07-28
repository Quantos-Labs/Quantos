// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Fuzz target for `DAGVertex` deserialization.
//!
//! Vertices arrive from P2P gossip after PQ-transport decryption and
//! `bincode::deserialize::<DAGVertex>` in `FastPath::receive_vertex`
//! (`src/consensus/fast_path.rs`). A malicious or compromised peer can
//! craft arbitrary bytes that reach this deserialization boundary.
//! The decode must never panic, OOM, or trigger unbounded allocation
//! regardless of input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use quantos::types::DAGVertex;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<DAGVertex>(data);
});
