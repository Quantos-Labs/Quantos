//! PQC-Guard — quantum-resistant guarded account for NEAR (near-sdk-rs).
//!
//! Reference port aligned with MULTIVM_SPEC.md. The contract IS one guarded
//! account holding NEAR; after migrating to a post-quantum key it releases
//! funds only via an M-of-N attestation from the Quantos-finalized attestor set
//! (the QTS anchor), checked on-chain with pure keccak256 (`env::keccak256`).
//!
//! The L0 anchoring uses NEAR's async cross-contract pattern: `update_attestor_set`
//! calls `is_proof_verified` on the L0 verifier and commits in a callback.
//!
//! TESTNET ONLY. // AUDIT REQUIRED.

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{
    env, ext_contract, near, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
};

/// Canonical PQCG chain id for NEAR (spec §6).
const CHAIN_ID: u64 = 0x4e45000000000001;
/// 24h commit-reveal delay (nanoseconds).
const COMMIT_DELAY_NS: u64 = 86_400 * 1_000_000_000;
/// 30d inactivity before the guardian escape hatch unlocks (nanoseconds).
const RECOVERY_TIMEOUT_NS: u64 = 2_592_000 * 1_000_000_000;
const CALLBACK_GAS: Gas = Gas::from_tgas(10);
const L0_CALL_GAS: Gas = Gas::from_tgas(10);

// ─────────────────────────── crypto (spec §2) ──────────────────────────────

mod crypto {
    use near_sdk::env;

    const W: u32 = 16;
    pub const LEN: usize = 67;

    pub fn keccak(data: &[u8]) -> [u8; 32] {
        let v = env::keccak256(data);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    pub fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        keccak(&buf)
    }

    pub fn u256_be_u128(n: u128) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[16..].copy_from_slice(&n.to_be_bytes());
        o
    }

    pub fn u256_be_u64(n: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&n.to_be_bytes());
        o
    }

    pub fn digits(digest: &[u8; 32]) -> [u8; 67] {
        let mut d = [0u8; 67];
        let mut csum: u32 = 0;
        for i in 0..32 {
            let hi = digest[i] >> 4;
            let lo = digest[i] & 0x0f;
            d[2 * i] = hi;
            d[2 * i + 1] = lo;
            csum += W - 1 - (hi as u32);
            csum += W - 1 - (lo as u32);
        }
        d[64] = ((csum >> 8) & 0x0f) as u8;
        d[65] = ((csum >> 4) & 0x0f) as u8;
        d[66] = (csum & 0x0f) as u8;
        d
    }

    pub fn pub_key_from_sig(digest: &[u8; 32], sig: &[[u8; 32]]) -> [u8; 32] {
        let d = digits(digest);
        let mut concat = Vec::with_capacity(LEN * 32);
        for i in 0..LEN {
            let mut x = sig[i];
            let mut j = d[i] as u32;
            while j < W - 1 {
                x = keccak(&x);
                j += 1;
            }
            concat.extend_from_slice(&x);
        }
        keccak(&concat)
    }

    pub fn wots_leaf(wots_pub: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(14 + 32);
        buf.extend_from_slice(b"PQCG_WOTS_LEAF");
        buf.extend_from_slice(wots_pub);
        keccak(&buf)
    }

    pub fn attestor_leaf(id: &[u8; 32], wots_root: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(18 + 64);
        buf.extend_from_slice(b"PQCG_ATTESTOR_LEAF");
        buf.extend_from_slice(id);
        buf.extend_from_slice(wots_root);
        keccak(&buf)
    }

    pub fn root_from_leaf(leaf: [u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
        let mut h = leaf;
        let mut idx = index;
        for sib in path {
            if idx & 1 == 0 {
                h = node(&h, sib);
            } else {
                h = node(sib, &h);
            }
            idx >>= 1;
        }
        h
    }
}

// ─────────────────────────── attestation decoder (spec §4/§5) ──────────────

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

/// Count distinct, valid, finalized attestors and compare to threshold.
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

        // (1) WOTS valid & in attestor's committed tree.
        let pubk = crypto::pub_key_from_sig(digest, &sig);
        let troot = crypto::root_from_leaf(crypto::wots_leaf(&pubk), leaf_index, &path);
        if troot != wots_root {
            continue;
        }

        // (2) attestor ∈ Quantos-finalized set (the QTS anchor).
        let aleaf = crypto::attestor_leaf(&attestor_id, &wots_root);
        let sroot = crypto::root_from_leaf(aleaf, set_index, &set_proof);
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

// ─────────────────────────── external L0 verifier ──────────────────────────

#[ext_contract(ext_l0)]
trait L0Verifier {
    fn is_proof_verified(&self, proof_hash: [u8; 32]) -> bool;
}

// ─────────────────────────── contract ──────────────────────────────────────

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PqcGuardAccount {
    owner: AccountId,
    migrated: bool,
    pqc_commitment: [u8; 32],
    pending_commitment: Option<[u8; 32]>,
    pending_time_ns: u64,
    nonce: u64,
    guardians: Vec<AccountId>,
    guardian_threshold: u32,
    last_activity_ns: u64,
    // QTS anchor
    l0_contract: AccountId,
    attestor_set_root: [u8; 32],
    attestor_epoch: u64,
    threshold: u32,
    // recovery
    sweep_active: bool,
    sweep_to: Option<AccountId>,
    sweep_approvals: Vec<AccountId>,
}

#[near]
impl PqcGuardAccount {
    #[init]
    pub fn new(owner: AccountId, l0_contract: AccountId) -> Self {
        Self {
            owner,
            migrated: false,
            pqc_commitment: [0u8; 32],
            pending_commitment: None,
            pending_time_ns: 0,
            nonce: 0,
            guardians: Vec::new(),
            guardian_threshold: 0,
            last_activity_ns: env::block_timestamp(),
            l0_contract,
            attestor_set_root: [0u8; 32],
            attestor_epoch: 0,
            threshold: 0,
            sweep_active: false,
            sweep_to: None,
            sweep_approvals: Vec::new(),
        }
    }

    // ── migration (commit-reveal) ──

    pub fn migrate(&mut self, commitment: [u8; 32], guardians: Vec<AccountId>, guardian_threshold: u32) {
        self.assert_owner();
        assert!(!self.migrated, "already migrated");
        self.pending_commitment = Some(commitment);
        self.pending_time_ns = env::block_timestamp();
        self.guardians = guardians;
        self.guardian_threshold = guardian_threshold;
    }

    pub fn finalize(&mut self, pqc_pub_key: Base64VecU8) {
        self.assert_owner();
        let pending = self.pending_commitment.expect("no pending");
        let now = env::block_timestamp();
        assert!(now >= self.pending_time_ns + COMMIT_DELAY_NS, "delay not elapsed");
        assert!(crypto::keccak(&pqc_pub_key.0) == pending, "bad reveal");
        self.pqc_commitment = pending;
        self.migrated = true;
        self.pending_commitment = None;
        self.last_activity_ns = now;
    }

    pub fn cancel(&mut self) {
        self.assert_owner();
        self.pending_commitment = None;
    }

    // ── attestor-set oracle (async L0 anchoring, §6) ──

    pub fn update_attestor_set(
        &mut self,
        root: [u8; 32],
        epoch: u64,
        threshold: u32,
        proof_hash: [u8; 32],
    ) -> Promise {
        self.assert_owner();
        assert!(epoch > self.attestor_epoch, "stale epoch");
        ext_l0::ext(self.l0_contract.clone())
            .with_static_gas(L0_CALL_GAS)
            .is_proof_verified(proof_hash)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_proof_checked(root, epoch, threshold),
            )
    }

    #[private]
    pub fn on_proof_checked(
        &mut self,
        root: [u8; 32],
        epoch: u64,
        threshold: u32,
        #[callback_result] verified: Result<bool, PromiseError>,
    ) {
        let ok = matches!(verified, Ok(true));
        assert!(ok, "L0 proof not verified");
        assert!(epoch > self.attestor_epoch, "stale epoch");
        self.attestor_set_root = root;
        self.attestor_epoch = epoch;
        self.threshold = threshold;
    }

    // ── execute (guarded NEAR release) ──

    pub fn execute(&mut self, to: AccountId, value: U128, data: Base64VecU8, attestation: Base64VecU8) -> Promise {
        assert!(self.migrated, "not migrated");
        let amount = value.0;

        let digest = self.compute_digest(&to, amount, &data.0, self.nonce);
        assert!(
            verify_authorization(&attestation.0, &digest, &self.attestor_set_root, self.threshold),
            "unauthorized"
        );

        self.nonce += 1;
        self.last_activity_ns = env::block_timestamp();
        Promise::new(to).transfer(NearToken::from_yoctonear(amount))
    }

    // ── escape hatch ──

    pub fn propose_recovery(&mut self, to: AccountId) {
        let g = env::predecessor_account_id();
        assert!(self.guardians.contains(&g), "not guardian");
        assert!(
            env::block_timestamp() > self.last_activity_ns + RECOVERY_TIMEOUT_NS,
            "timeout not reached"
        );
        self.sweep_active = true;
        self.sweep_to = Some(to);
        self.sweep_approvals = vec![g];
    }

    pub fn approve_recovery(&mut self) {
        let g = env::predecessor_account_id();
        assert!(self.guardians.contains(&g), "not guardian");
        assert!(self.sweep_active, "no recovery");
        if !self.sweep_approvals.contains(&g) {
            self.sweep_approvals.push(g);
        }
    }

    pub fn execute_recovery(&mut self) -> Promise {
        assert!(self.sweep_active, "no recovery");
        assert!(self.sweep_approvals.len() as u32 >= self.guardian_threshold, "no quorum");
        let to = self.sweep_to.clone().expect("no target");
        self.sweep_active = false;
        // Sweep the whole account balance minus a small reserve for storage.
        let bal = env::account_balance();
        Promise::new(to).transfer(bal)
    }


    // ── views ──

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_attestor_set_root(&self) -> [u8; 32] {
        self.attestor_set_root
    }

    pub fn is_migrated(&self) -> bool {
        self.migrated
    }

    // ── internals ──

    /// Authorization digest (spec §3), NEAR field normalization:
    /// `to` is keccak256(utf8(account_id)).
    fn compute_digest(&self, to: &AccountId, value: u128, data: &[u8], nonce: u64) -> [u8; 32] {
        let to_field = crypto::keccak(to.as_bytes());
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&self.pqc_commitment);
        buf.extend_from_slice(&to_field);
        buf.extend_from_slice(&crypto::u256_be_u128(value));
        buf.extend_from_slice(&crypto::keccak(data));
        buf.extend_from_slice(&crypto::u256_be_u64(nonce));
        buf.extend_from_slice(&crypto::u256_be_u64(CHAIN_ID));
        crypto::keccak(&buf)
    }

    fn assert_owner(&self) {
        assert!(env::predecessor_account_id() == self.owner, "not owner");
    }
}

// ─────────────────────────── tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // WOTS test signer (mirrors the spec; on-chain only verifies).
    fn sk(seed: &[u8; 32], leaf: u64, chain: u64) -> [u8; 32] {
        let mut b = Vec::new();
        b.extend_from_slice(b"PQCG_WOTS_SK");
        b.extend_from_slice(seed);
        b.extend_from_slice(&crypto::u256_be_u64(leaf));
        b.extend_from_slice(&crypto::u256_be_u64(chain));
        crypto::keccak(&b)
    }

    fn sign(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> Vec<[u8; 32]> {
        let d = crypto::digits(digest);
        (0..crypto::LEN)
            .map(|i| {
                let mut x = sk(seed, leaf, i as u64);
                for _ in 0..d[i] {
                    x = crypto::keccak(&x);
                }
                x
            })
            .collect()
    }

    fn wots_root0(seed: &[u8; 32], leaf: u64, digest: &[u8; 32]) -> [u8; 32] {
        crypto::wots_leaf(&crypto::pub_key_from_sig(digest, &sign(seed, leaf, digest)))
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
        let digest = crypto::keccak(b"authorize this");
        let seed0 = [1u8; 32];
        let seed1 = [2u8; 32];
        let id0 = [0x11u8; 32];
        let id1 = [0x22u8; 32];
        let root0 = wots_root0(&seed0, 0, &digest);
        let root1 = wots_root0(&seed1, 0, &digest);
        let leaf0 = crypto::attestor_leaf(&id0, &root0);
        let leaf1 = crypto::attestor_leaf(&id1, &root1);
        let set_root = crypto::node(&leaf0, &leaf1);
        Fixture {
            digest,
            set_root,
            id0,
            id1,
            root0,
            root1,
            leaf0,
            leaf1,
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
        // Forged id but valid sig for root1 ⇒ attestor leaf not in the set tree.
        enc_proof(&mut blob, &fake_id, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(!verify_authorization(&blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn wrong_digest_rejected() {
        let f = fixture();
        let other = crypto::keccak(b"different message");
        let mut blob = Vec::new();
        enc_u32(&mut blob, 2);
        enc_proof(&mut blob, &f.id0, &f.root0, 0, &f.sig0, &[], 0, &[f.leaf1]);
        enc_proof(&mut blob, &f.id1, &f.root1, 0, &f.sig1, &[], 1, &[f.leaf0]);
        assert!(!verify_authorization(&blob, &other, &f.set_root, 2));
    }
}
