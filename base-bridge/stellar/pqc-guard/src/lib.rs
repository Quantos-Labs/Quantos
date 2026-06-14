#![no_std]
//! PQC-Guard — quantum-resistant guarded account for Stellar (Soroban).
//!
//! Reference port aligned with MULTIVM_SPEC.md. Holds a SAC/token balance and,
//! after migrating to a post-quantum key, releases funds only via an M-of-N
//! attestation from the Quantos-finalized attestor set (the QTS anchor),
//! checked on-chain with pure keccak256 (`env.crypto().keccak256`).
//!
//! NOTE (SDK): this targets soroban-sdk 21 where `keccak256` returns
//! `BytesN<32>`. If your SDK returns `Hash<32>`, append `.to_bytes()` to the
//! keccak calls in `crypto`.
//!
//! TESTNET ONLY. // AUDIT REQUIRED.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, Vec,
};

/// Canonical PQCG chain id for Stellar (spec §6).
const CHAIN_ID: u64 = 0x5354000000000001;
/// 24h commit-reveal delay (seconds).
const COMMIT_DELAY_S: u64 = 86_400;
/// 30d inactivity before the guardian escape hatch unlocks (seconds).
const RECOVERY_TIMEOUT_S: u64 = 2_592_000;

// ─────────────────────────── crypto (spec §2) ──────────────────────────────

mod crypto {
    use soroban_sdk::{Bytes, BytesN, Env, Vec};

    const W: u32 = 16;
    pub const LEN: u32 = 67;

    /// Single hashing entry point. soroban-sdk 21 returns `Hash<32>`, which we
    /// normalize to `BytesN<32>` via `into()`.
    pub fn keccak_bytes(env: &Env, b: &Bytes) -> BytesN<32> {
        env.crypto().keccak256(b).into()
    }

    fn keccak32(env: &Env, x: &BytesN<32>) -> BytesN<32> {
        let b = Bytes::from_array(env, &x.to_array());
        keccak_bytes(env, &b)
    }

    pub fn node(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
        let mut buf = Bytes::new(env);
        buf.extend_from_array(&a.to_array());
        buf.extend_from_array(&b.to_array());
        keccak_bytes(env, &buf)
    }

    pub fn u256_be_u64(n: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        let b = n.to_be_bytes();
        let mut k = 0;
        while k < 8 {
            o[24 + k] = b[k];
            k += 1;
        }
        o
    }

    pub fn u256_be_i128(n: i128) -> [u8; 32] {
        let mut o = [0u8; 32];
        let b = (n as u128).to_be_bytes();
        let mut k = 0;
        while k < 16 {
            o[16 + k] = b[k];
            k += 1;
        }
        o
    }

    /// 64 message + 3 checksum base-16 digits of a 32-byte digest.
    pub fn digits(digest: &BytesN<32>) -> [u8; 67] {
        let a = digest.to_array();
        let mut d = [0u8; 67];
        let mut csum: u32 = 0;
        let mut i = 0usize;
        while i < 32 {
            let hi = a[i] >> 4;
            let lo = a[i] & 0x0f;
            d[2 * i] = hi;
            d[2 * i + 1] = lo;
            csum += W - 1 - (hi as u32);
            csum += W - 1 - (lo as u32);
            i += 1;
        }
        d[64] = ((csum >> 8) & 0x0f) as u8;
        d[65] = ((csum >> 4) & 0x0f) as u8;
        d[66] = (csum & 0x0f) as u8;
        d
    }

    /// Recompute the compressed WOTS public key from a signature over `digest`.
    pub fn pub_key_from_sig(env: &Env, digest: &BytesN<32>, sig: &Vec<BytesN<32>>) -> BytesN<32> {
        let d = digits(digest);
        let mut concat = Bytes::new(env);
        let mut i: u32 = 0;
        while i < LEN {
            let mut x = sig.get(i).unwrap();
            let mut j = d[i as usize] as u32;
            while j < W - 1 {
                x = keccak32(env, &x);
                j += 1;
            }
            concat.extend_from_array(&x.to_array());
            i += 1;
        }
        keccak_bytes(env, &concat)
    }

    pub fn wots_leaf(env: &Env, wots_pub: &BytesN<32>) -> BytesN<32> {
        let mut buf = Bytes::from_slice(env, b"PQCG_WOTS_LEAF");
        buf.extend_from_array(&wots_pub.to_array());
        keccak_bytes(env, &buf)
    }

    pub fn attestor_leaf(env: &Env, id: &BytesN<32>, wots_root: &BytesN<32>) -> BytesN<32> {
        let mut buf = Bytes::from_slice(env, b"PQCG_ATTESTOR_LEAF");
        buf.extend_from_array(&id.to_array());
        buf.extend_from_array(&wots_root.to_array());
        keccak_bytes(env, &buf)
    }

    pub fn root_from_leaf(env: &Env, leaf: BytesN<32>, index: u64, path: &Vec<BytesN<32>>) -> BytesN<32> {
        let mut h = leaf;
        let mut idx = index;
        let mut i: u32 = 0;
        let n = path.len();
        while i < n {
            let sib = path.get(i).unwrap();
            if idx & 1 == 0 {
                h = node(env, &h, &sib);
            } else {
                h = node(env, &sib, &h);
            }
            idx >>= 1;
            i += 1;
        }
        h
    }
}

// ─────────────────────────── shared verify (spec §5) ───────────────────────

fn read_u32(blob: &Bytes, off: &mut u32) -> u32 {
    let mut v: u32 = 0;
    let mut i: u32 = 0;
    while i < 4 {
        v = (v << 8) | (blob.get(*off + i).unwrap() as u32);
        i += 1;
    }
    *off += 4;
    v
}

fn read_u64(blob: &Bytes, off: &mut u32) -> u64 {
    let mut v: u64 = 0;
    let mut i: u32 = 0;
    while i < 8 {
        v = (v << 8) | (blob.get(*off + i).unwrap() as u64);
        i += 1;
    }
    *off += 8;
    v
}

fn read_word(env: &Env, blob: &Bytes, off: &mut u32) -> BytesN<32> {
    let mut a = [0u8; 32];
    let mut i: u32 = 0;
    while i < 32 {
        a[i as usize] = blob.get(*off + i).unwrap();
        i += 1;
    }
    *off += 32;
    BytesN::from_array(env, &a)
}

fn read_words(env: &Env, blob: &Bytes, off: &mut u32, count: u32) -> Vec<BytesN<32>> {
    let mut out = Vec::new(env);
    let mut i: u32 = 0;
    while i < count {
        out.push_back(read_word(env, blob, off));
        i += 1;
    }
    out
}

fn contains(seen: &Vec<BytesN<32>>, x: &BytesN<32>) -> bool {
    let mut i: u32 = 0;
    while i < seen.len() {
        if &seen.get(i).unwrap() == x {
            return true;
        }
        i += 1;
    }
    false
}

/// Count distinct, valid, finalized attestors and compare to threshold.
pub fn verify_authorization(
    env: &Env,
    blob: &Bytes,
    digest: &BytesN<32>,
    set_root: &BytesN<32>,
    threshold: u32,
) -> bool {
    let mut off: u32 = 0;
    let count = read_u32(blob, &mut off);
    let mut seen: Vec<BytesN<32>> = Vec::new(env);
    let mut valid: u32 = 0;
    let mut c: u32 = 0;
    while c < count {
        let attestor_id = read_word(env, blob, &mut off);
        let wots_root = read_word(env, blob, &mut off);
        let leaf_index = read_u64(blob, &mut off);
        let sig_len = read_u32(blob, &mut off);
        let sig = read_words(env, blob, &mut off, sig_len);
        let path_len = read_u32(blob, &mut off);
        let path = read_words(env, blob, &mut off, path_len);
        let set_index = read_u64(blob, &mut off);
        let sp_len = read_u32(blob, &mut off);
        let set_proof = read_words(env, blob, &mut off, sp_len);
        c += 1;

        if contains(&seen, &attestor_id) {
            continue;
        }

        // (1) WOTS valid & in attestor's committed tree.
        let pubk = crypto::pub_key_from_sig(env, digest, &sig);
        let troot = crypto::root_from_leaf(env, crypto::wots_leaf(env, &pubk), leaf_index, &path);
        if troot != wots_root {
            continue;
        }

        // (2) attestor ∈ Quantos-finalized set (the QTS anchor).
        let aleaf = crypto::attestor_leaf(env, &attestor_id, &wots_root);
        let sroot = crypto::root_from_leaf(env, aleaf, set_index, &set_proof);
        if &sroot != set_root {
            continue;
        }

        seen.push_back(attestor_id);
        valid += 1;
        if valid >= threshold {
            return true;
        }
    }
    valid >= threshold
}

// ─────────────────────────── attestor-set oracle (§6) ──────────────────────

#[contracttype]
enum OracleKey {
    Admin,
    L0,
    Root,
    Epoch,
    Threshold,
}

#[contract]
pub struct AttestorOracle;

#[contractimpl]
impl AttestorOracle {
    pub fn init_oracle(env: Env, admin: Address, l0: Address) {
        admin.require_auth();
        let s = env.storage().instance();
        s.set(&OracleKey::Admin, &admin);
        s.set(&OracleKey::L0, &l0);
        s.set(&OracleKey::Epoch, &0u64);
    }

    /// Publish a Quantos-finalized attestor set, gated by a VERIFIED L0 proof.
    pub fn update_set(
        env: Env,
        root: BytesN<32>,
        epoch: u64,
        threshold: u32,
        proof_hash: BytesN<32>,
    ) {
        let s = env.storage().instance();
        let admin: Address = s.get(&OracleKey::Admin).unwrap();
        admin.require_auth();

        let cur: u64 = s.get(&OracleKey::Epoch).unwrap_or(0);
        assert!(epoch > cur, "stale epoch");

        let l0: Address = s.get(&OracleKey::L0).unwrap();
        let verified: bool = env.invoke_contract(
            &l0,
            &Symbol::new(&env, "is_proof_verified"),
            vec![&env, proof_hash.into_val(&env)],
        );
        assert!(verified, "L0 proof not verified");

        s.set(&OracleKey::Root, &root);
        s.set(&OracleKey::Epoch, &epoch);
        s.set(&OracleKey::Threshold, &threshold);
    }

    pub fn root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&OracleKey::Root).unwrap()
    }

    pub fn threshold(env: Env) -> u32 {
        env.storage().instance().get(&OracleKey::Threshold).unwrap_or(0)
    }

    pub fn epoch(env: Env) -> u64 {
        env.storage().instance().get(&OracleKey::Epoch).unwrap_or(0)
    }
}

// ─────────────────────────── guarded account (§7) ──────────────────────────

#[contracttype]
enum AcctKey {
    Owner,
    Token,
    Oracle,
    Migrated,
    Commitment,
    Pending,
    PendingTime,
    Nonce,
    Guardians,
    GThreshold,
    LastActivity,
    SweepActive,
    SweepTo,
    SweepApprovals,
}

#[contract]
pub struct PqcGuardAccount;

#[contractimpl]
impl PqcGuardAccount {
    /// Create the guarded account, owned (pre-migration) by `owner`, holding `token`.
    pub fn init(env: Env, owner: Address, token: Address, oracle: Address) {
        owner.require_auth();
        let s = env.storage().instance();
        s.set(&AcctKey::Owner, &owner);
        s.set(&AcctKey::Token, &token);
        s.set(&AcctKey::Oracle, &oracle);
        s.set(&AcctKey::Migrated, &false);
        s.set(&AcctKey::Nonce, &0u64);
        s.set(&AcctKey::LastActivity, &env.ledger().timestamp());
        s.set(&AcctKey::SweepActive, &false);
    }

    /// Deposit `amount` of the configured token into this account.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let token: Address = env.storage().instance().get(&AcctKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        client.transfer(&from, &env.current_contract_address(), &amount);
        env.storage().instance().set(&AcctKey::LastActivity, &env.ledger().timestamp());
    }

    /// Commit to migrating to a post-quantum key (owner only, commit-reveal).
    pub fn migrate(
        env: Env,
        commitment: BytesN<32>,
        guardians: Vec<Address>,
        guardian_threshold: u32,
    ) {
        let s = env.storage().instance();
        let owner: Address = s.get(&AcctKey::Owner).unwrap();
        owner.require_auth();
        let migrated: bool = s.get(&AcctKey::Migrated).unwrap_or(false);
        assert!(!migrated, "already migrated");
        s.set(&AcctKey::Pending, &commitment);
        s.set(&AcctKey::PendingTime, &env.ledger().timestamp());
        s.set(&AcctKey::Guardians, &guardians);
        s.set(&AcctKey::GThreshold, &guardian_threshold);
    }

    /// Reveal the PQC public key and finalize migration after the delay.
    pub fn finalize(env: Env, pqc_pub_key: Bytes) {
        let s = env.storage().instance();
        let owner: Address = s.get(&AcctKey::Owner).unwrap();
        owner.require_auth();
        let pending: BytesN<32> = s.get(&AcctKey::Pending).expect("no pending");
        let pending_time: u64 = s.get(&AcctKey::PendingTime).unwrap();
        let now = env.ledger().timestamp();
        assert!(now >= pending_time + COMMIT_DELAY_S, "delay not elapsed");
        let revealed = crypto::keccak_bytes(&env, &pqc_pub_key);
        assert!(revealed == pending, "bad reveal");

        s.set(&AcctKey::Commitment, &pending);
        s.set(&AcctKey::Migrated, &true);
        s.remove(&AcctKey::Pending);
        s.set(&AcctKey::LastActivity, &now);
    }

    /// Cancel a pending (not yet finalized) migration.
    pub fn cancel(env: Env) {
        let s = env.storage().instance();
        let owner: Address = s.get(&AcctKey::Owner).unwrap();
        owner.require_auth();
        s.remove(&AcctKey::Pending);
    }

    /// Release `value` of the token to `to`, authorized ONLY by an M-of-N
    /// attestation over the current nonce. Anyone may relay.
    pub fn execute(env: Env, to: Address, value: i128, data: Bytes, attestation: Bytes) {
        let s = env.storage().instance();
        let migrated: bool = s.get(&AcctKey::Migrated).unwrap_or(false);
        assert!(migrated, "not migrated");

        let account: BytesN<32> = s.get(&AcctKey::Commitment).unwrap();
        let nonce: u64 = s.get(&AcctKey::Nonce).unwrap_or(0);
        let tf = to_field(&env, &to);
        let digest = compute_digest(&env, &account, &tf, value, &data, nonce);

        let oracle: Address = s.get(&AcctKey::Oracle).unwrap();
        let set_root: BytesN<32> =
            env.invoke_contract(&oracle, &Symbol::new(&env, "root"), vec![&env]);
        let threshold: u32 =
            env.invoke_contract(&oracle, &Symbol::new(&env, "threshold"), vec![&env]);

        assert!(
            verify_authorization(&env, &attestation, &digest, &set_root, threshold),
            "unauthorized"
        );

        let token: Address = s.get(&AcctKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(&env.current_contract_address(), &to, &value);

        s.set(&AcctKey::Nonce, &(nonce + 1));
        s.set(&AcctKey::LastActivity, &env.ledger().timestamp());
    }

    // ── escape hatch (funds never freeze) ──

    pub fn propose_recovery(env: Env, guardian: Address, to: Address) {
        guardian.require_auth();
        let s = env.storage().instance();
        assert!(is_guardian(&env, &guardian), "not guardian");
        let last: u64 = s.get(&AcctKey::LastActivity).unwrap();
        assert!(env.ledger().timestamp() > last + RECOVERY_TIMEOUT_S, "timeout not reached");
        s.set(&AcctKey::SweepActive, &true);
        s.set(&AcctKey::SweepTo, &to);
        let mut approvals: Vec<Address> = Vec::new(&env);
        approvals.push_back(guardian);
        s.set(&AcctKey::SweepApprovals, &approvals);
    }

    pub fn approve_recovery(env: Env, guardian: Address) {
        guardian.require_auth();
        let s = env.storage().instance();
        assert!(is_guardian(&env, &guardian), "not guardian");
        let active: bool = s.get(&AcctKey::SweepActive).unwrap_or(false);
        assert!(active, "no recovery");
        let mut approvals: Vec<Address> = s.get(&AcctKey::SweepApprovals).unwrap();
        if !approvals.contains(&guardian) {
            approvals.push_back(guardian);
            s.set(&AcctKey::SweepApprovals, &approvals);
        }
    }

    pub fn execute_recovery(env: Env) {
        let s = env.storage().instance();
        let active: bool = s.get(&AcctKey::SweepActive).unwrap_or(false);
        assert!(active, "no recovery");
        let approvals: Vec<Address> = s.get(&AcctKey::SweepApprovals).unwrap();
        let gthreshold: u32 = s.get(&AcctKey::GThreshold).unwrap_or(0);
        assert!(approvals.len() >= gthreshold, "no quorum");

        let to: Address = s.get(&AcctKey::SweepTo).unwrap();
        let token: Address = s.get(&AcctKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        let bal = client.balance(&env.current_contract_address());
        client.transfer(&env.current_contract_address(), &to, &bal);
        s.set(&AcctKey::SweepActive, &false);
    }

    pub fn get_nonce(env: Env) -> u64 {
        env.storage().instance().get(&AcctKey::Nonce).unwrap_or(0)
    }
}

// ── helpers (account) ──

/// Authorization digest (spec §3), Stellar field normalization:
/// `to` is keccak256(utf8(strkey address)).
fn compute_digest(
    env: &Env,
    account: &BytesN<32>,
    to_field: &BytesN<32>,
    value: i128,
    data: &Bytes,
    nonce: u64,
) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.extend_from_array(&account.to_array());
    buf.extend_from_array(&to_field.to_array());
    buf.extend_from_array(&crypto::u256_be_i128(value));
    let dh = crypto::keccak_bytes(env, data);
    buf.extend_from_array(&dh.to_array());
    buf.extend_from_array(&crypto::u256_be_u64(nonce));
    buf.extend_from_array(&crypto::u256_be_u64(CHAIN_ID));
    crypto::keccak_bytes(env, &buf)
}

/// keccak256(utf8(address strkey)) — normalizes a Stellar Address to 32 bytes.
fn to_field(env: &Env, to: &Address) -> BytesN<32> {
    let s = to.to_string();
    let len = s.len() as usize;
    let mut buf = [0u8; 64];
    s.copy_into_slice(&mut buf[..len]);
    crypto::keccak_bytes(env, &Bytes::from_slice(env, &buf[..len]))
}

fn is_guardian(env: &Env, who: &Address) -> bool {
    let s = env.storage().instance();
    let guardians: Vec<Address> = s.get(&AcctKey::Guardians).unwrap_or(Vec::new(env));
    guardians.contains(who)
}

// keep symbol_short import used (events could be added later)
// ─────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const W_MINUS_1: u32 = 15; // W=16, private in crypto mod

    fn sk(env: &Env, seed: &[u8; 32], leaf: u64, chain: u64) -> BytesN<32> {
        let mut buf = Bytes::new(env);
        buf.extend_from_slice(b"PQCG_WOTS_SK");
        buf.extend_from_array(seed);
        buf.extend_from_array(&crypto::u256_be_u64(leaf));
        buf.extend_from_array(&crypto::u256_be_u64(chain));
        crypto::keccak_bytes(env, &buf)
    }

    fn sign(env: &Env, seed: &[u8; 32], leaf: u64, digest: &BytesN<32>) -> Vec<BytesN<32>> {
        let d = crypto::digits(digest);
        let mut sig = Vec::new(env);
        let mut i: u32 = 0;
        while i < crypto::LEN {
            let mut x = sk(env, seed, leaf, i as u64);
            let mut j = d[i as usize] as u32;
            while j < W_MINUS_1 {
                x = crypto::keccak_bytes(env, &Bytes::from_array(env, &x.to_array()));
                j += 1;
            }
            sig.push_back(x);
            i += 1;
        }
        sig
    }

    fn wots_root0(env: &Env, seed: &[u8; 32], leaf: u64, digest: &BytesN<32>) -> BytesN<32> {
        let sig = sign(env, seed, leaf, digest);
        let pubk = crypto::pub_key_from_sig(env, digest, &sig);
        crypto::wots_leaf(env, &pubk)
    }

    fn enc_u32(env: &Env, n: u32) -> Bytes {
        let mut b = Bytes::new(env);
        b.push_back(((n >> 24) & 0xff) as u8);
        b.push_back(((n >> 16) & 0xff) as u8);
        b.push_back(((n >> 8) & 0xff) as u8);
        b.push_back((n & 0xff) as u8);
        b
    }

    fn enc_u64(env: &Env, n: u64) -> Bytes {
        let mut b = Bytes::new(env);
        b.push_back(((n >> 56) & 0xff) as u8);
        b.push_back(((n >> 48) & 0xff) as u8);
        b.push_back(((n >> 40) & 0xff) as u8);
        b.push_back(((n >> 32) & 0xff) as u8);
        b.push_back(((n >> 24) & 0xff) as u8);
        b.push_back(((n >> 16) & 0xff) as u8);
        b.push_back(((n >> 8) & 0xff) as u8);
        b.push_back((n & 0xff) as u8);
        b
    }

    fn enc_words(env: &Env, ws: &Vec<BytesN<32>>) -> Bytes {
        let mut b = enc_u32(env, ws.len());
        let mut i: u32 = 0;
        while i < ws.len() {
            b.extend_from_array(&ws.get(i).unwrap().to_array());
            i += 1;
        }
        b
    }

    fn word_byte(env: &Env, byte: u8) -> BytesN<32> {
        let a = [byte; 32];
        BytesN::from_array(env, &a)
    }

    struct Fixture {
        env: Env,
        digest: BytesN<32>,
        set_root: BytesN<32>,
        id0: BytesN<32>,
        id1: BytesN<32>,
        root0: BytesN<32>,
        root1: BytesN<32>,
        leaf0: BytesN<32>,
        leaf1: BytesN<32>,
        sig0: Vec<BytesN<32>>,
        sig1: Vec<BytesN<32>>,
    }

    fn build_blob(
        env: &Env,
        n: u32,
        proofs: &[(
            &BytesN<32>, &BytesN<32>, u64,
            &Vec<BytesN<32>>, &Vec<BytesN<32>>, u64, &Vec<BytesN<32>>,
        )],
    ) -> Bytes {
        let mut blob = enc_u32(env, n);
        for (id, root, li, sig, path, si, sp) in proofs {
            blob.extend_from_array(&id.to_array());
            blob.extend_from_array(&root.to_array());
            blob.append(&enc_u64(env, *li));
            blob.append(&enc_words(env, sig));
            blob.append(&enc_words(env, path));
            blob.append(&enc_u64(env, *si));
            blob.append(&enc_words(env, sp));
        }
        blob
    }

    fn fixture() -> Fixture {
        let env = Env::default();
        let digest = crypto::keccak_bytes(&env, &Bytes::from_slice(&env, b"authorize this"));
        let seed0 = [1u8; 32];
        let seed1 = [2u8; 32];
        let id0 = word_byte(&env, 0x11);
        let id1 = word_byte(&env, 0x22);
        let root0 = wots_root0(&env, &seed0, 0, &digest);
        let root1 = wots_root0(&env, &seed1, 0, &digest);
        let leaf0 = crypto::attestor_leaf(&env, &id0, &root0);
        let leaf1 = crypto::attestor_leaf(&env, &id1, &root1);
        let set_root = crypto::node(&env, &leaf0, &leaf1);
        let sig0 = sign(&env, &seed0, 0, &digest);
        let sig1 = sign(&env, &seed1, 0, &digest);
        Fixture { env, digest, set_root, id0, id1, root0, root1, leaf0, leaf1, sig0, sig1 }
    }

    #[test]
    fn quorum_reached() {
        let f = fixture();
        let empty: Vec<BytesN<32>> = Vec::new(&f.env);
        let sp0 = Vec::from_array(&f.env, [f.leaf1.clone()]);
        let sp1 = Vec::from_array(&f.env, [f.leaf0.clone()]);
        let blob = build_blob(&f.env, 2, &[
            (&f.id0, &f.root0, 0, &f.sig0, &empty, 0, &sp0),
            (&f.id1, &f.root1, 0, &f.sig1, &empty, 1, &sp1),
        ]);
        assert!(verify_authorization(&f.env, &blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn quorum_not_reached() {
        let f = fixture();
        let empty: Vec<BytesN<32>> = Vec::new(&f.env);
        let sp0 = Vec::from_array(&f.env, [f.leaf1.clone()]);
        let blob = build_blob(&f.env, 1, &[
            (&f.id0, &f.root0, 0, &f.sig0, &empty, 0, &sp0),
        ]);
        assert!(!verify_authorization(&f.env, &blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn non_member_rejected() {
        let f = fixture();
        let fake_id = word_byte(&f.env, 0xDE);
        let empty: Vec<BytesN<32>> = Vec::new(&f.env);
        let sp0 = Vec::from_array(&f.env, [f.leaf1.clone()]);
        let sp1 = Vec::from_array(&f.env, [f.leaf0.clone()]);
        let blob = build_blob(&f.env, 2, &[
            (&f.id0, &f.root0, 0, &f.sig0, &empty, 0, &sp0),
            (&fake_id, &f.root1, 0, &f.sig1, &empty, 1, &sp1),
        ]);
        assert!(!verify_authorization(&f.env, &blob, &f.digest, &f.set_root, 2));
    }

    #[test]
    fn wrong_digest_rejected() {
        let f = fixture();
        let other = crypto::keccak_bytes(&f.env, &Bytes::from_slice(&f.env, b"different message"));
        let empty: Vec<BytesN<32>> = Vec::new(&f.env);
        let sp0 = Vec::from_array(&f.env, [f.leaf1.clone()]);
        let sp1 = Vec::from_array(&f.env, [f.leaf0.clone()]);
        let blob = build_blob(&f.env, 2, &[
            (&f.id0, &f.root0, 0, &f.sig0, &empty, 0, &sp0),
            (&f.id1, &f.root1, 0, &f.sig1, &empty, 1, &sp1),
        ]);
        assert!(!verify_authorization(&f.env, &blob, &other, &f.set_root, 2));
    }
}

#[allow(dead_code)]
fn _touch() -> Symbol {
    symbol_short!("PQCG")
}
