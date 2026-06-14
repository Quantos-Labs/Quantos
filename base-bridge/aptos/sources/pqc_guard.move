// PQC-Guard — quantum-resistant guarded vault for Aptos (Move).
//
// Reference port aligned with MULTIVM_SPEC.md. A user moves APT into a
// GuardedVault resource and, after migrating to a post-quantum key, can only
// release funds via an M-of-N attestation from the Quantos-finalized attestor
// set (the QTS anchor), checked on-chain with pure keccak256.
//
// Aptos model notes:
//   - State lives in account-stored resources (move_to / borrow_global).
//   - The vault is stored under the OWNER's account; a relayer calls `execute`
//     passing the owner address, so authority comes from the proof, not msg.
//   - VM capability (spec §7): Move has no generic dispatch, so `execute` is a
//     guarded coin release to a recipient, not an arbitrary call.
//
// TESTNET ONLY. // AUDIT REQUIRED.
module quantos::pqc_guard {
    use std::signer;
    use std::vector;
    use std::bcs;
    use aptos_std::aptos_hash;
    use aptos_framework::timestamp;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::aptos_account;
    use aptos_framework::event;
    use quantos::pqc_guard_crypto as crypto;
    use quantos::l0_verifier;

    // ── parameters ───────────────────────────────────────────────────────--

    /// Canonical PQCG chain id for Aptos (spec §6).
    const CHAIN_ID: u64 = 0x4150000000000001;
    /// 24h commit-reveal delay (microseconds).
    const COMMIT_DELAY_US: u64 = 86_400_000_000;
    /// 30d inactivity before the guardian escape hatch unlocks (microseconds).
    const RECOVERY_TIMEOUT_US: u64 = 2_592_000_000_000;

    // ── errors ───────────────────────────────────────────────────────────--

    const E_NOT_OWNER: u64 = 0;
    const E_ALREADY_MIGRATED: u64 = 1;
    const E_NOT_MIGRATED: u64 = 2;
    const E_NO_PENDING: u64 = 3;
    const E_DELAY_NOT_ELAPSED: u64 = 4;
    const E_BAD_REVEAL: u64 = 5;
    const E_UNAUTHORIZED: u64 = 6;
    const E_STALE_EPOCH: u64 = 7;
    const E_PROOF_NOT_VERIFIED: u64 = 8;
    const E_NOT_GUARDIAN: u64 = 9;
    const E_TIMEOUT_NOT_REACHED: u64 = 10;
    const E_NO_QUORUM: u64 = 11;
    const E_INSUFFICIENT_FUNDS: u64 = 12;

    // ── resources ────────────────────────────────────────────────────────--

    /// The QTS anchor: the Quantos-finalized attestor set, fed by L0 proofs.
    /// Stored under the admin account.
    struct AttestorOracle has key {
        admin: address,
        attestor_set_root: vector<u8>, // 32 bytes
        epoch: u64,
        threshold: u64,
    }

    /// A user's quantum-resistant vault holding APT. Stored under the owner.
    struct GuardedVault has key {
        owner: address,
        migrated: bool,
        pqc_commitment: vector<u8>,     // 32 bytes (active key commitment)
        pending_commitment: vector<u8>, // 32 bytes (during commit-reveal)
        pending_time_us: u64,           // 0 if no pending migration
        nonce: u64,
        funds: Coin<AptosCoin>,
        guardians: vector<address>,
        guardian_threshold: u64,
        last_activity_us: u64,
        sweep_active: bool,
        sweep_to: address,
        sweep_approvals: vector<address>,
    }

    // ── events ───────────────────────────────────────────────────────────--

    #[event]
    struct Migrated has drop, store { vault: address, commitment: vector<u8> }
    #[event]
    struct Executed has drop, store { vault: address, to: address, value: u64, nonce: u64 }
    #[event]
    struct Swept has drop, store { vault: address, to: address, amount: u64 }

    // ── oracle ───────────────────────────────────────────────────────────--

    /// Create the attestor-set oracle under the admin account.
    public entry fun init_oracle(admin: &signer) {
        move_to(admin, AttestorOracle {
            admin: signer::address_of(admin),
            attestor_set_root: empty32(),
            epoch: 0,
            threshold: 0,
        });
    }

    /// Publish a Quantos-finalized attestor set. Gated by a VERIFIED L0 proof
    /// (spec §6): the proof must already be accepted by the chain's L0 verifier.
    public entry fun update_attestor_set(
        admin: &signer,
        l0_registry_addr: address,
        root: vector<u8>,
        epoch: u64,
        threshold: u64,
        proof_hash: vector<u8>,
    ) acquires AttestorOracle {
        let addr = signer::address_of(admin);
        let oracle = borrow_global_mut<AttestorOracle>(addr);
        assert!(oracle.admin == addr, E_NOT_OWNER);
        assert!(epoch > oracle.epoch, E_STALE_EPOCH);
        assert!(l0_verifier::is_proof_verified(l0_registry_addr, proof_hash), E_PROOF_NOT_VERIFIED);
        oracle.attestor_set_root = root;
        oracle.epoch = epoch;
        oracle.threshold = threshold;
    }

    // ── vault lifecycle ────────────────────────────────────────────────────

    /// Create an empty vault under the sender's account (pre-migration).
    public entry fun create_vault(owner: &signer) {
        let addr = signer::address_of(owner);
        move_to(owner, GuardedVault {
            owner: addr,
            migrated: false,
            pqc_commitment: empty32(),
            pending_commitment: empty32(),
            pending_time_us: 0,
            nonce: 0,
            funds: coin::zero<AptosCoin>(),
            guardians: vector::empty<address>(),
            guardian_threshold: 0,
            last_activity_us: timestamp::now_microseconds(),
            sweep_active: false,
            sweep_to: @0x0,
            sweep_approvals: vector::empty<address>(),
        });
    }

    /// Deposit APT into a vault (anyone may fund it).
    public entry fun deposit(funder: &signer, vault_owner: address, amount: u64) acquires GuardedVault {
        let c = coin::withdraw<AptosCoin>(funder, amount);
        let vault = borrow_global_mut<GuardedVault>(vault_owner);
        coin::merge(&mut vault.funds, c);
        vault.last_activity_us = timestamp::now_microseconds();
    }

    /// Commit to migrating to a post-quantum key (owner only, commit-reveal).
    public entry fun migrate(
        owner: &signer,
        commitment: vector<u8>,
        guardians: vector<address>,
        guardian_threshold: u64,
    ) acquires GuardedVault {
        let addr = signer::address_of(owner);
        let vault = borrow_global_mut<GuardedVault>(addr);
        assert!(vault.owner == addr, E_NOT_OWNER);
        assert!(!vault.migrated, E_ALREADY_MIGRATED);
        vault.pending_commitment = commitment;
        vault.pending_time_us = timestamp::now_microseconds();
        vault.guardians = guardians;
        vault.guardian_threshold = guardian_threshold;
    }

    /// Reveal the PQC public key and finalize migration after the delay.
    public entry fun finalize_migration(owner: &signer, pqc_pub_key: vector<u8>) acquires GuardedVault {
        let addr = signer::address_of(owner);
        let vault = borrow_global_mut<GuardedVault>(addr);
        assert!(vault.owner == addr, E_NOT_OWNER);
        assert!(vault.pending_time_us != 0, E_NO_PENDING);
        let now = timestamp::now_microseconds();
        assert!(now >= vault.pending_time_us + COMMIT_DELAY_US, E_DELAY_NOT_ELAPSED);
        assert!(aptos_hash::keccak256(pqc_pub_key) == vault.pending_commitment, E_BAD_REVEAL);

        vault.pqc_commitment = vault.pending_commitment;
        vault.migrated = true;
        vault.pending_commitment = empty32();
        vault.pending_time_us = 0;
        vault.last_activity_us = now;

        event::emit(Migrated { vault: addr, commitment: vault.pqc_commitment });
    }

    /// Cancel a pending (not yet finalized) migration.
    public entry fun cancel_migration(owner: &signer) acquires GuardedVault {
        let addr = signer::address_of(owner);
        let vault = borrow_global_mut<GuardedVault>(addr);
        assert!(vault.owner == addr, E_NOT_OWNER);
        vault.pending_commitment = empty32();
        vault.pending_time_us = 0;
    }

    // ── execute (guarded coin release) ──────────────────────────────────────

    /// Release `value` APT to `to`, authorized ONLY by an M-of-N attestation
    /// over the current nonce. Anyone may relay; authority comes from the proof.
    public entry fun execute(
        _relayer: &signer,
        vault_owner: address,
        oracle_addr: address,
        to: address,
        value: u64,
        data: vector<u8>,
        attestation: vector<u8>,
    ) acquires GuardedVault, AttestorOracle {
        // Read the finalized set from the oracle, then drop that borrow.
        let oracle = borrow_global<AttestorOracle>(oracle_addr);
        let set_root = oracle.attestor_set_root;
        let threshold = oracle.threshold;

        let vault = borrow_global_mut<GuardedVault>(vault_owner);
        assert!(vault.migrated, E_NOT_MIGRATED);
        assert!(coin::value(&vault.funds) >= value, E_INSUFFICIENT_FUNDS);

        let digest = compute_digest(&vault.pqc_commitment, to, value, &data, vault.nonce);
        assert!(verify_authorization(&attestation, &digest, &set_root, threshold), E_UNAUTHORIZED);

        let c = coin::extract(&mut vault.funds, value);
        aptos_account::deposit_coins<AptosCoin>(to, c);

        vault.nonce = vault.nonce + 1;
        vault.last_activity_us = timestamp::now_microseconds();

        event::emit(Executed { vault: vault_owner, to, value, nonce: vault.nonce });
    }

    // ── escape hatch (funds never freeze) ───────────────────────────────────

    /// A guardian proposes sweeping all funds to `to` after inactivity timeout.
    public entry fun propose_recovery(guardian: &signer, vault_owner: address, to: address) acquires GuardedVault {
        let sender = signer::address_of(guardian);
        let vault = borrow_global_mut<GuardedVault>(vault_owner);
        assert!(is_guardian(vault, sender), E_NOT_GUARDIAN);
        assert!(timestamp::now_microseconds() > vault.last_activity_us + RECOVERY_TIMEOUT_US, E_TIMEOUT_NOT_REACHED);
        vault.sweep_active = true;
        vault.sweep_to = to;
        vault.sweep_approvals = vector::empty<address>();
        vector::push_back(&mut vault.sweep_approvals, sender);
    }

    /// Another guardian approves the in-flight recovery.
    public entry fun approve_recovery(guardian: &signer, vault_owner: address) acquires GuardedVault {
        let sender = signer::address_of(guardian);
        let vault = borrow_global_mut<GuardedVault>(vault_owner);
        assert!(is_guardian(vault, sender), E_NOT_GUARDIAN);
        assert!(vault.sweep_active, E_NO_QUORUM);
        if (!contains_addr(&vault.sweep_approvals, sender)) {
            vector::push_back(&mut vault.sweep_approvals, sender);
        };
    }

    /// Execute the recovery once the guardian quorum is met.
    public entry fun execute_recovery(vault_owner: address) acquires GuardedVault {
        let vault = borrow_global_mut<GuardedVault>(vault_owner);
        assert!(vault.sweep_active, E_NO_QUORUM);
        assert!(vector::length(&vault.sweep_approvals) >= vault.guardian_threshold, E_NO_QUORUM);
        let amount = coin::value(&vault.funds);
        let all = coin::extract(&mut vault.funds, amount);
        aptos_account::deposit_coins<AptosCoin>(vault.sweep_to, all);
        vault.sweep_active = false;
        event::emit(Swept { vault: vault_owner, to: vault.sweep_to, amount });
    }

    // ── verification (spec §5) ──────────────────────────────────────────────

    /// Authorization digest (spec §3), Aptos field normalization.
    public fun compute_digest(
        account: &vector<u8>,
        to: address,
        value: u64,
        data: &vector<u8>,
        nonce: u64,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, *account);
        vector::append(&mut buf, bcs::to_bytes(&to));
        vector::append(&mut buf, crypto::u256_be_from_u64(value));
        vector::append(&mut buf, aptos_hash::keccak256(*data));
        vector::append(&mut buf, crypto::u256_be_from_u64(nonce));
        vector::append(&mut buf, crypto::u256_be_from_u64(CHAIN_ID));
        aptos_hash::keccak256(buf)
    }

    /// Count distinct, valid, finalized attestors and compare to threshold.
    public fun verify_authorization(
        blob: &vector<u8>,
        digest: &vector<u8>,
        set_root: &vector<u8>,
        threshold: u64,
    ): bool {
        let off: u64 = 0;
        let count = read_u32(blob, &mut off);
        let seen = vector::empty<vector<u8>>();
        let valid: u64 = 0;
        let c: u64 = 0;
        while (c < count) {
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
            c = c + 1;

            if (contains_word(&seen, &attestor_id)) { continue };

            // (1) WOTS valid & in attestor's committed tree.
            let pubk = crypto::pub_key_from_sig(digest, &sig);
            let troot = crypto::root_from_leaf(crypto::wots_leaf(&pubk), leaf_index, &path);
            if (troot != wots_root) { continue };

            // (2) attestor ∈ Quantos-finalized set (the QTS anchor).
            let aleaf = crypto::attestor_leaf(&attestor_id, &wots_root);
            let sroot = crypto::root_from_leaf(aleaf, set_index, &set_proof);
            if (sroot != *set_root) { continue };

            vector::push_back(&mut seen, attestor_id);
            valid = valid + 1;
            if (valid >= threshold) { return true };
        };
        valid >= threshold
    }

    // ── decoder helpers (canonical binary format, spec §4) ──────────────────

    fun read_u32(blob: &vector<u8>, off: &mut u64): u64 {
        let v: u64 = 0;
        let i = 0;
        while (i < 4) {
            v = (v << 8) | (*vector::borrow(blob, *off + i) as u64);
            i = i + 1;
        };
        *off = *off + 4;
        v
    }

    fun read_u64(blob: &vector<u8>, off: &mut u64): u64 {
        let v: u64 = 0;
        let i = 0;
        while (i < 8) {
            v = (v << 8) | (*vector::borrow(blob, *off + i) as u64);
            i = i + 1;
        };
        *off = *off + 8;
        v
    }

    fun read_word(blob: &vector<u8>, off: &mut u64): vector<u8> {
        let w = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut w, *vector::borrow(blob, *off + i));
            i = i + 1;
        };
        *off = *off + 32;
        w
    }

    fun read_words(blob: &vector<u8>, off: &mut u64, count: u64): vector<vector<u8>> {
        let out = vector::empty<vector<u8>>();
        let i = 0;
        while (i < count) {
            vector::push_back(&mut out, read_word(blob, off));
            i = i + 1;
        };
        out
    }

    fun contains_word(seen: &vector<vector<u8>>, x: &vector<u8>): bool {
        let n = vector::length(seen);
        let i = 0;
        while (i < n) {
            if (vector::borrow(seen, i) == x) { return true };
            i = i + 1;
        };
        false
    }

    fun contains_addr(arr: &vector<address>, x: address): bool {
        let n = vector::length(arr);
        let i = 0;
        while (i < n) {
            if (*vector::borrow(arr, i) == x) { return true };
            i = i + 1;
        };
        false
    }

    fun is_guardian(vault: &GuardedVault, who: address): bool {
        contains_addr(&vault.guardians, who)
    }

    fun empty32(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, 0u8); i = i + 1; };
        v
    }
}
