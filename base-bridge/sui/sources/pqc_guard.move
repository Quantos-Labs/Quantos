// PQC-Guard — quantum-resistant guarded vault for Sui (Move).
//
// Reference non-EVM port (see MULTIVM_SPEC.md). A user moves SUI into a
// GuardedVault and, after migrating to a post-quantum key, can only release
// those funds via an M-of-N attestation from the Quantos-finalized attestor set
// (the QTS anchor), checked on-chain with pure keccak256.
//
// VM capability note (spec §7): Sui/Move has no generic dynamic dispatch, so the
// v1 `execute` is a guarded *coin release* to a recipient, not an arbitrary call.
//
// TESTNET ONLY. // AUDIT REQUIRED.
module quantos::pqc_guard {
    use std::vector;
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::clock::{Self, Clock};
    use sui::address;
    use sui::hash;
    use sui::event;
    use quantos::pqc_guard_crypto as crypto;
    use quantos::l0_verifier::{Self, L0Registry};

    // ── parameters ───────────────────────────────────────────────────────--

    /// Canonical PQCG chain id for Sui (spec §6).
    const CHAIN_ID: u64 = 0x5549000000000001;
    /// 24h commit-reveal delay (ms).
    const COMMIT_DELAY_MS: u64 = 86_400_000;
    /// 30d inactivity before the guardian escape hatch unlocks (ms).
    const RECOVERY_TIMEOUT_MS: u64 = 2_592_000_000;

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

    // ── objects ──────────────────────────────────────────────────────────--

    /// The QTS anchor: the Quantos-finalized attestor set, fed by L0 proofs.
    public struct AttestorOracle has key {
        id: UID,
        admin: address,
        attestor_set_root: vector<u8>, // 32 bytes
        epoch: u64,
        threshold: u64,
    }

    /// A user's quantum-resistant vault holding SUI.
    public struct GuardedVault has key {
        id: UID,
        owner: address,
        migrated: bool,
        pqc_commitment: vector<u8>,     // 32 bytes (active key commitment)
        pending_commitment: vector<u8>, // 32 bytes (during commit-reveal)
        pending_time_ms: u64,           // 0 if no pending migration
        nonce: u64,
        funds: Balance<SUI>,
        guardians: vector<address>,
        guardian_threshold: u64,
        last_activity_ms: u64,
        // single in-flight recovery proposal
        sweep_active: bool,
        sweep_to: address,
        sweep_approvals: vector<address>,
    }

    // ── events ───────────────────────────────────────────────────────────--

    public struct Migrated has copy, drop { vault: address, commitment: vector<u8> }
    public struct Executed has copy, drop { vault: address, to: address, value: u64, nonce: u64 }
    public struct Swept has copy, drop { vault: address, to: address, amount: u64 }

    // ── oracle ───────────────────────────────────────────────────────────--

    /// Create the shared attestor-set oracle (admin = sender).
    public entry fun create_oracle(ctx: &mut TxContext) {
        transfer::share_object(AttestorOracle {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            attestor_set_root: empty32(),
            epoch: 0,
            threshold: 0,
        });
    }

    /// Publish a Quantos-finalized attestor set. Gated by a VERIFIED L0 proof
    /// (spec §6): the proof must already be accepted by the chain's L0 verifier.
    public entry fun update_attestor_set(
        oracle: &mut AttestorOracle,
        registry: &L0Registry,
        root: vector<u8>,
        epoch: u64,
        threshold: u64,
        proof_hash: vector<u8>,
        ctx: &mut TxContext,
    ) {
        assert!(tx_context::sender(ctx) == oracle.admin, E_NOT_OWNER);
        assert!(epoch > oracle.epoch, E_STALE_EPOCH);
        assert!(l0_verifier::is_proof_verified(registry, proof_hash), E_PROOF_NOT_VERIFIED);
        oracle.attestor_set_root = root;
        oracle.epoch = epoch;
        oracle.threshold = threshold;
    }

    // ── vault lifecycle ────────────────────────────────────────────────────

    /// Create a shared, empty vault owned (pre-migration) by the sender.
    public entry fun create_vault(clock: &Clock, ctx: &mut TxContext) {
        transfer::share_object(GuardedVault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            migrated: false,
            pqc_commitment: empty32(),
            pending_commitment: empty32(),
            pending_time_ms: 0,
            nonce: 0,
            funds: balance::zero<SUI>(),
            guardians: vector::empty<address>(),
            guardian_threshold: 0,
            last_activity_ms: clock::timestamp_ms(clock),
            sweep_active: false,
            sweep_to: @0x0,
            sweep_approvals: vector::empty<address>(),
        });
    }

    /// Deposit SUI into the vault (anyone may fund it).
    public entry fun deposit(vault: &mut GuardedVault, c: Coin<SUI>, clock: &Clock) {
        balance::join(&mut vault.funds, coin::into_balance(c));
        vault.last_activity_ms = clock::timestamp_ms(clock);
    }

    /// Commit to migrating to a post-quantum key (owner only, commit-reveal).
    public entry fun migrate(
        vault: &mut GuardedVault,
        commitment: vector<u8>,
        guardians: vector<address>,
        guardian_threshold: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(tx_context::sender(ctx) == vault.owner, E_NOT_OWNER);
        assert!(!vault.migrated, E_ALREADY_MIGRATED);
        vault.pending_commitment = commitment;
        vault.pending_time_ms = clock::timestamp_ms(clock);
        vault.guardians = guardians;
        vault.guardian_threshold = guardian_threshold;
    }

    /// Reveal the PQC public key and finalize migration after the delay.
    public entry fun finalize_migration(
        vault: &mut GuardedVault,
        pqc_pub_key: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(tx_context::sender(ctx) == vault.owner, E_NOT_OWNER);
        assert!(vault.pending_time_ms != 0, E_NO_PENDING);
        let now = clock::timestamp_ms(clock);
        assert!(now >= vault.pending_time_ms + COMMIT_DELAY_MS, E_DELAY_NOT_ELAPSED);
        assert!(hash::keccak256(&pqc_pub_key) == vault.pending_commitment, E_BAD_REVEAL);

        vault.pqc_commitment = vault.pending_commitment;
        vault.migrated = true;
        vault.pending_commitment = empty32();
        vault.pending_time_ms = 0;
        vault.last_activity_ms = now;

        event::emit(Migrated { vault: object::uid_to_address(&vault.id), commitment: vault.pqc_commitment });
    }

    /// Cancel a pending (not yet finalized) migration.
    public entry fun cancel_migration(vault: &mut GuardedVault, ctx: &mut TxContext) {
        assert!(tx_context::sender(ctx) == vault.owner, E_NOT_OWNER);
        vault.pending_commitment = empty32();
        vault.pending_time_ms = 0;
    }

    // ── execute (guarded coin release) ──────────────────────────────────────

    /// Release `value` SUI to `to`, authorized ONLY by an M-of-N attestation
    /// over the current nonce. Anyone may relay; authority comes from the proof.
    public entry fun execute(
        vault: &mut GuardedVault,
        oracle: &AttestorOracle,
        to: address,
        value: u64,
        data: vector<u8>,
        attestation: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(vault.migrated, E_NOT_MIGRATED);
        assert!(balance::value(&vault.funds) >= value, E_INSUFFICIENT_FUNDS);

        let digest = compute_digest(&vault.pqc_commitment, to, value, &data, vault.nonce);
        assert!(
            verify_authorization(&attestation, &digest, &oracle.attestor_set_root, oracle.threshold),
            E_UNAUTHORIZED
        );

        let part = balance::split(&mut vault.funds, value);
        transfer::public_transfer(coin::from_balance(part, ctx), to);

        vault.nonce = vault.nonce + 1;
        vault.last_activity_ms = clock::timestamp_ms(clock);

        event::emit(Executed { vault: object::uid_to_address(&vault.id), to, value, nonce: vault.nonce });
    }

    // ── escape hatch (funds never freeze) ───────────────────────────────────

    /// A guardian proposes sweeping all funds to `to` after inactivity timeout.
    public entry fun propose_recovery(
        vault: &mut GuardedVault,
        to: address,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let sender = tx_context::sender(ctx);
        assert!(is_guardian(vault, sender), E_NOT_GUARDIAN);
        assert!(clock::timestamp_ms(clock) > vault.last_activity_ms + RECOVERY_TIMEOUT_MS, E_TIMEOUT_NOT_REACHED);
        vault.sweep_active = true;
        vault.sweep_to = to;
        vault.sweep_approvals = vector::empty<address>();
        vector::push_back(&mut vault.sweep_approvals, sender);
    }

    /// Another guardian approves the in-flight recovery.
    public entry fun approve_recovery(vault: &mut GuardedVault, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        assert!(is_guardian(vault, sender), E_NOT_GUARDIAN);
        assert!(vault.sweep_active, E_NO_QUORUM);
        if (!contains_addr(&vault.sweep_approvals, sender)) {
            vector::push_back(&mut vault.sweep_approvals, sender);
        };
    }

    /// Execute the recovery once the guardian quorum is met.
    public entry fun execute_recovery(vault: &mut GuardedVault, ctx: &mut TxContext) {
        assert!(vault.sweep_active, E_NO_QUORUM);
        assert!(vector::length(&vault.sweep_approvals) >= vault.guardian_threshold, E_NO_QUORUM);
        let amount = balance::value(&vault.funds);
        let all = balance::split(&mut vault.funds, amount);
        transfer::public_transfer(coin::from_balance(all, ctx), vault.sweep_to);
        vault.sweep_active = false;
        event::emit(Swept { vault: object::uid_to_address(&vault.id), to: vault.sweep_to, amount });
    }

    // ── verification (spec §5) ──────────────────────────────────────────────

    /// Authorization digest (spec §3), Sui field normalization.
    public fun compute_digest(
        account: &vector<u8>,
        to: address,
        value: u64,
        data: &vector<u8>,
        nonce: u64,
    ): vector<u8> {
        let mut buf = vector::empty<u8>();
        vector::append(&mut buf, *account);
        vector::append(&mut buf, address::to_bytes(to));
        vector::append(&mut buf, crypto::u256_be_from_u64(value));
        vector::append(&mut buf, hash::keccak256(data));
        vector::append(&mut buf, crypto::u256_be_from_u64(nonce));
        vector::append(&mut buf, crypto::u256_be_from_u64(CHAIN_ID));
        hash::keccak256(&buf)
    }

    /// Count distinct, valid, finalized attestors and compare to threshold.
    public fun verify_authorization(
        blob: &vector<u8>,
        digest: &vector<u8>,
        set_root: &vector<u8>,
        threshold: u64,
    ): bool {
        let mut off: u64 = 0;
        let count = read_u32(blob, &mut off);
        let mut seen = vector::empty<vector<u8>>();
        let mut valid: u64 = 0;
        let mut c: u64 = 0;
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
        let mut v: u64 = 0;
        let mut i = 0;
        while (i < 4) {
            v = (v << 8) | (*vector::borrow(blob, *off + i) as u64);
            i = i + 1;
        };
        *off = *off + 4;
        v
    }

    fun read_u64(blob: &vector<u8>, off: &mut u64): u64 {
        let mut v: u64 = 0;
        let mut i = 0;
        while (i < 8) {
            v = (v << 8) | (*vector::borrow(blob, *off + i) as u64);
            i = i + 1;
        };
        *off = *off + 8;
        v
    }

    fun read_word(blob: &vector<u8>, off: &mut u64): vector<u8> {
        let mut w = vector::empty<u8>();
        let mut i = 0;
        while (i < 32) {
            vector::push_back(&mut w, *vector::borrow(blob, *off + i));
            i = i + 1;
        };
        *off = *off + 32;
        w
    }

    fun read_words(blob: &vector<u8>, off: &mut u64, count: u64): vector<vector<u8>> {
        let mut out = vector::empty<vector<u8>>();
        let mut i = 0;
        while (i < count) {
            vector::push_back(&mut out, read_word(blob, off));
            i = i + 1;
        };
        out
    }

    fun contains_word(seen: &vector<vector<u8>>, x: &vector<u8>): bool {
        let n = vector::length(seen);
        let mut i = 0;
        while (i < n) {
            if (vector::borrow(seen, i) == x) { return true };
            i = i + 1;
        };
        false
    }

    fun contains_addr(arr: &vector<address>, x: address): bool {
        let n = vector::length(arr);
        let mut i = 0;
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
        let mut v = vector::empty<u8>();
        let mut i = 0;
        while (i < 32) { vector::push_back(&mut v, 0u8); i = i + 1; };
        v
    }
}
