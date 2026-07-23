// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// PQC-Guard — quantum-resistant guarded account for Internet Computer (ICP)
//
// Reference port aligned with MULTIVM_SPEC.md. The canister IS one guarded
// account holding ICP cycles/e8s; after migrating to a post-quantum key it
// releases funds only via an M-of-N attestation from the Quantos-finalized
// attestor set (the QTS anchor), checked on-chain with pure keccak256.
//
// ICP provides keccak256 via the `sha3` crate and persistent state via
// `ic_cdk::storage`. The L0 anchoring uses a canister-call pattern:
// `update_attestor_set` calls `is_proof_verified` on the L0 verifier canister
// via `call_raw`.
//
// TESTNET ONLY. // AUDIT REQUIRED.

use ic_cdk::api::{self, call_raw, time_ns};
use ic_cdk::{caller, storage};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

// ─────────────────────────── constants (spec §8) ────────────────────────────

const W: u8 = 16;
const LEN: usize = 67;
const COMMIT_DELAY_NS: u64 = 86_400 * 1_000_000_000; // 24h
const RECOVERY_TIMEOUT_NS: u64 = 2_592_000 * 1_000_000_000; // 30d

// Canonical PQCG chain id for ICP (spec §6).
const CHAIN_ID: u64 = 0x4943500000000001;

// ─────────────────────────── crypto (spec §2) ───────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn keccak_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    keccak256(&buf)
}

fn u256_be_u128(n: u128) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&n.to_be_bytes());
    o
}

fn u256_be_u64(n: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&n.to_be_bytes());
    o
}

fn digits(digest: &[u8; 32]) -> [u8; 67] {
    let mut d = [0u8; 67];
    let mut csum: u32 = 0;
    for i in 0..32 {
        let hi = digest[i] >> 4;
        let lo = digest[i] & 0x0f;
        d[2 * i] = hi;
        d[2 * i + 1] = lo;
        csum += (W - 1) as u32 - hi as u32;
        csum += (W - 1) as u32 - lo as u32;
    }
    d[64] = ((csum >> 8) & 0x0f) as u8;
    d[65] = ((csum >> 4) & 0x0f) as u8;
    d[66] = (csum & 0x0f) as u8;
    d
}

fn pub_key_from_sig(digest: &[u8; 32], sig: &[[u8; 32]]) -> [u8; 32] {
    let d = digits(digest);
    let mut concat = Vec::with_capacity(LEN * 32);
    for i in 0..LEN {
        let mut x = sig[i];
        let mut j = d[i] as u8;
        while j < W - 1 {
            x = keccak256(&x);
            j += 1;
        }
        concat.extend_from_slice(&x);
    }
    keccak256(&concat)
}

fn wots_leaf(wots_pub: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 32);
    buf.extend_from_slice(b"PQCG_WOTS_LEAF");
    buf.extend_from_slice(wots_pub);
    keccak256(&buf)
}

fn attestor_leaf(id: &[u8; 32], wots_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(18 + 64);
    buf.extend_from_slice(b"PQCG_ATTESTOR_LEAF");
    buf.extend_from_slice(id);
    buf.extend_from_slice(wots_root);
    keccak256(&buf)
}

fn root_from_leaf(leaf: [u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
    let mut h = leaf;
    let mut idx = index;
    for sib in path {
        if idx & 1 == 0 {
            h = keccak_pair(&h, sib);
        } else {
            h = keccak_pair(sib, &h);
        }
        idx >>= 1;
    }
    h
}

// ─────────────────────────── attestation decoder (spec §4/§5) ───────────────

fn read_u32(b: &[u8], off: &mut usize) -> u32 {
    let mut v = 0u32;
    for i in 0..4 {
        v = (v << 8) | (b[*off + i] as u32);
    }
    *off += 4;
    v
}

fn read_u64(b: &[u8], off: &mut usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v = (v << 8) | (b[*off + i] as u64);
    }
    *off += 8;
    v
}

fn read_word(b: &[u8], off: &mut usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&b[*off..*off + 32]);
    *off += 32;
    w
}

fn read_words(b: &[u8], off: &mut usize, count: u32) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(read_word(b, off));
    }
    out
}

fn verify_authorization(blob: &[u8], digest: &[u8; 32], set_root: &[u8; 32], threshold: u32) -> bool {
    let mut off = 0usize;
    let count = read_u32(blob, &mut off);
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut valid: u32 = 0;
    for _ in 0..count {
        let attestor_id = read_word(blob, &mut off);
        let wots_root = read_word(blob, &mut off);
        let leaf_index = read_u64(blob, &mut off);
        let sig_len = read_u32(blob, &mut off);
        let sig = read_words(blob, &mut off, sig_len);
        let path_len = read_u32(blob, &mut off);
        let path = read_words(blob, &mut off, path_len);
        let set_index = read_u64(blob, &mut off);
        let sp_len = read_u32(blob, &mut off);
        let set_proof = read_words(blob, &mut off, sp_len);

        if seen.contains(&attestor_id) {
            continue;
        }

        let pubk = pub_key_from_sig(digest, &sig);
        let troot = root_from_leaf(wots_leaf(&pubk), leaf_index, &path);
        if troot != wots_root {
            continue;
        }

        let aleaf = attestor_leaf(&attestor_id, &wots_root);
        let sroot = root_from_leaf(aleaf, set_index, &set_proof);
        if &sroot != set_root {
            continue;
        }

        seen.push(attestor_id);
        valid += 1;
        if valid >= threshold {
            return true;
        }
    }
    valid >= threshold
}

// ─────────────────────────── contract state ─────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
struct PqcGuardState {
    owner: String,
    migrated: bool,
    pqc_commitment: [u8; 32],
    pending_commitment: Option<[u8; 32]>,
    pending_time_ns: u64,
    nonce: u64,
    guardians: Vec<String>,
    guardian_threshold: u32,
    last_activity_ns: u64,
    // QTS anchor
    l0_canister_id: String,
    attestor_set_root: [u8; 32],
    attestor_epoch: u64,
    threshold: u32,
    // Recovery
    sweep_active: bool,
    sweep_to: Option<String>,
    sweep_approvals: Vec<String>,
}

const STATE_KEY: &[u8] = b"pqc_guard_state";

fn get_state() -> PqcGuardState {
    storage::stable_get(STATE_KEY)
        .map(|bytes| {
            candid::decode_one::<PqcGuardState>(&bytes).unwrap_or_default()
        })
        .unwrap_or_default()
}

fn put_state(state: &PqcGuardState) {
    let bytes = candid::encode_one(state).unwrap_or_default();
    storage::stable_set(STATE_KEY, &bytes);
}

fn assert_owner(state: &PqcGuardState) {
    if caller().to_string() != state.owner {
        ic_cdk::trap("not owner");
    }
}

// ─────────────────────────── canister API ───────────────────────────────────

#[ic_cdk::init]
fn init(owner: String, l0_canister_id: String) {
    let state = PqcGuardState {
        owner,
        l0_canister_id,
        last_activity_ns: time_ns(),
        ..Default::default()
    };
    put_state(&state);
}

// ── Migration: commit → (24h) → reveal/finalize ──

#[ic_cdk::update]
fn migrate(commitment: [u8; 32], guardians: Vec<String>, guardian_threshold: u32) {
    let mut state = get_state();
    assert_owner(&state);
    if state.migrated {
        ic_cdk::trap("already migrated");
    }
    if guardians.is_empty() || guardian_threshold == 0 || guardian_threshold as usize > guardians.len() {
        ic_cdk::trap("invalid guardian set");
    }
    state.pending_commitment = Some(commitment);
    state.pending_time_ns = time_ns();
    state.guardians = guardians;
    state.guardian_threshold = guardian_threshold;
    put_state(&state);
}

#[ic_cdk::update]
fn finalize_migration(pqc_pub_key: Vec<u8>) {
    let mut state = get_state();
    assert_owner(&state);
    let pending = state.pending_commitment.expect("no pending");
    let now = time_ns();
    if now < state.pending_time_ns + COMMIT_DELAY_NS {
        ic_cdk::trap("delay not elapsed");
    }
    if keccak256(&pqc_pub_key) != pending {
        ic_cdk::trap("bad reveal");
    }
    state.pqc_commitment = pending;
    state.migrated = true;
    state.pending_commitment = None;
    state.last_activity_ns = now;
    put_state(&state);
}

#[ic_cdk::update]
fn cancel_migration() {
    let mut state = get_state();
    assert_owner(&state);
    state.pending_commitment = None;
    put_state(&state);
}

// ── Attestor-set oracle (L0 anchoring via canister call) ──

#[ic_cdk::update]
async fn update_attestor_set(
    root: [u8; 32],
    epoch: u64,
    threshold: u32,
    proof_hash: [u8; 32],
) {
    let mut state = get_state();
    assert_owner(&state);
    if epoch <= state.attestor_epoch {
        ic_cdk::trap("stale epoch");
    }

    // Call L0 verifier canister: is_proof_verified(proof_hash) -> bool
    let l0_id = state.l0_canister_id.clone();
    let arg = candid::encode_one(proof_hash).unwrap_or_default();
    let raw = call_raw(l0_id.parse().expect("bad canister id"), "is_proof_verified", &arg, 0)
        .await
        .expect("L0 call failed");
    let verified: bool = candid::decode_one(&raw).expect("decode failed");
    if !verified {
        ic_cdk::trap("L0 proof not verified");
    }

    state.attestor_set_root = root;
    state.attestor_epoch = epoch;
    state.threshold = threshold;
    put_state(&state);
}

// ── Execute: PQC-authorized asset release ──

#[ic_cdk::update]
fn execute(to: String, value_e8s: u128, data: Vec<u8>, attestation: Vec<u8>) {
    let mut state = get_state();
    if !state.migrated {
        ic_cdk::trap("not migrated");
    }

    let digest = compute_digest(&state, &to, value_e8s, &data, state.nonce);
    if !verify_authorization(&attestation, &digest, &state.attestor_set_root, state.threshold) {
        ic_cdk::trap("unauthorized");
    }

    state.nonce += 1;
    state.last_activity_ns = time_ns();
    put_state(&state);

    // Transfer e8s to the recipient principal.
    // In production, use ic_cdk::api::call::call_raw to the ledger canister.
    // For POC, we record the intent.
}

// ── Escape hatch ──

#[ic_cdk::update]
fn propose_recovery(to: String) {
    let mut state = get_state();
    let g = caller().to_string();
    if !state.guardians.contains(&g) {
        ic_cdk::trap("not guardian");
    }
    if time_ns() <= state.last_activity_ns + RECOVERY_TIMEOUT_NS {
        ic_cdk::trap("timeout not reached");
    }
    state.sweep_active = true;
    state.sweep_to = Some(to);
    state.sweep_approvals = vec![g];
    put_state(&state);
}

#[ic_cdk::update]
fn approve_recovery() {
    let mut state = get_state();
    let g = caller().to_string();
    if !state.guardians.contains(&g) {
        ic_cdk::trap("not guardian");
    }
    if !state.sweep_active {
        ic_cdk::trap("no recovery");
    }
    if !state.sweep_approvals.contains(&g) {
        state.sweep_approvals.push(g);
        put_state(&state);
    }
}

#[ic_cdk::update]
fn execute_recovery() {
    let mut state = get_state();
    if !state.sweep_active {
        ic_cdk::trap("no recovery");
    }
    if state.sweep_approvals.len() as u32 < state.guardian_threshold {
        ic_cdk::trap("no quorum");
    }
    let to = state.sweep_to.clone().expect("no target");
    state.sweep_active = false;
    put_state(&state);
    // In production, transfer all balance to `to` via ledger canister.
}

// ── Views ──

#[ic_cdk::query]
fn get_nonce() -> u64 {
    get_state().nonce
}

#[ic_cdk::query]
fn is_migrated() -> bool {
    get_state().migrated
}

#[ic_cdk::query]
fn get_attestor_set_root() -> [u8; 32] {
    get_state().attestor_set_root
}

// ── Internals ──

fn compute_digest(state: &PqcGuardState, to: &str, value: u128, data: &[u8], nonce: u64) -> [u8; 32] {
    // ICP field normalization: to = keccak256(utf8(principal_string))
    let to_field = keccak256(to.as_bytes());
    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(&state.pqc_commitment);
    buf.extend_from_slice(&to_field);
    buf.extend_from_slice(&u256_be_u128(value));
    buf.extend_from_slice(&keccak256(data));
    buf.extend_from_slice(&u256_be_u64(nonce));
    buf.extend_from_slice(&u256_be_u64(CHAIN_ID));
    keccak256(&buf)
}

// ─────────────────────────── tests ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: &[u8; 32], leaf: u64, chain: u64) -> [u8; 32] {
        let mut b = Vec::new();
        b.extend_from_slice(b"PQCG_WOTS_SK");
        b.extend_from_slice(seed);
        b.extend_from_slice(&u256_be_u64(leaf));
        b.extend_from_slice(&u256_be_u64(chain));
        keccak256(&b)
    }

    fn sign(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> Vec<[u8; 32]> {
        let d = digits(digest);
        (0..LEN)
            .map(|i| {
                let mut x = sk(seed, leaf, i as u64);
                for _ in 0..d[i] {
                    x = keccak256(&x);
                }
                x
            })
            .collect()
    }

    fn wots_root0(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> [u8; 32] {
        wots_leaf(&pub_key_from_sig(digest, &sign(seed, leaf, digest)))
    }

    fn enc_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_be_bytes());
    }
    fn enc_u64(v: &mut Vec<u8>, n: u64) {
        v.extend_from_slice(&n.to_be_bytes());
    }
    fn enc_words(v: &mut Vec<u8>, ws: &[[u8; 32]]) {
        enc_u32(v, ws.len() as u32);
        for w in ws {
            v.extend_from_slice(w);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn enc_proof(
        v: &mut Vec<u8>,
        id: &[u8; 32],
        root: &[u8; 32],
        leaf_index: u64,
        sig: &[[u8; 32]],
        path: &[[u8; 32]],
        set_index: u64,
        set_proof: &[[u8; 32]],
    ) {
        v.extend_from_slice(id);
        v.extend_from_slice(root);
        enc_u64(v, leaf_index);
        enc_words(v, sig);
        enc_words(v, path);
        enc_u64(v, set_index);
        enc_words(v, set_proof);
    }

    struct Fixture {
        digest: [u8; 32],
        set_root: [u8; 32],
        id0: [u8; 32],
        id1: [u8; 32],
        root0: [u8; 32],
        root1: [u8; 32],
        leaf0: [u8; 32],
        leaf1: [u8; 32],
        sig0: Vec<[u8; 32]>,
        sig1: Vec<[u8; 32]>,
    }

    fn fixture() -> Fixture {
        let digest = keccak256(b"authorize this");
        let seed0 = [1u8; 32];
        let seed1 = [2u8; 32];
        let id0 = [0x11u8; 32];
        let id1 = [0x22u8; 32];
        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);
        let leaf0 = attestor_leaf(&id0, &root0);
        let leaf1 = attestor_leaf(&id1, &root1);
        let set_root = keccak_pair(&leaf0, &leaf1);
        Fixture {
            digest, set_root, id0, id1, root0, root1, leaf0, leaf1,
            sig0: sign(&seed0, 0, &digest),
            sig1: sign(&seed1, 0, &digest),
        }
    }

    #[test]
    fn quorum_reached() {
        let f = fixture();
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &f.id1, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn quorum_not_reached() {
        let f = fixture();
        let mut blob = Vec::new();
        enc_u32(&mut blob, 1);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        assert!(!verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn non_member_rejected() {
        let f = fixture();
        let fake_id = [0xDEu8; 32];
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &fake_id, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(!verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn wrong_digest_rejected() {
        let f = fixture();
        let other = keccak256(b"different message");
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &f.id1, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(!verify_authorization(&blob, &other, &f.set_root, 2));
    }
}
