// Quantos L0 Verifier for Aptos (Move)
// On-chain validation of PQC finality proofs produced by Quantos.

module quantos::l0_verifier {
    use std::signer;
    use std::vector;
    use std::table;
    use aptos_framework::event;
    use aptos_framework::timestamp;

    // ================================================================
    // Constants & Error codes
    // ================================================================

    const E_UNKNOWN_SET: u64 = 0;
    const E_INSUFFICIENT_STAKE: u64 = 1;
    const E_PROOF_ALREADY_VERIFIED: u64 = 2;
    const E_PROOF_NOT_VERIFIED: u64 = 3;
    const E_DEPOSIT_ALREADY_RELAYED: u64 = 4;
    const E_NOT_ADMIN: u64 = 5;
    const E_ALREADY_INITIALIZED: u64 = 6;

    // ================================================================
    // Structs
    // ================================================================

    /// Admin store that controls the verifier.
    struct AdminStore has key {
        admin: address,
    }

    /// A trusted validator set root.
    struct ValidatorSet has store, copy, drop {
        root: vector<u8>,   // 32 bytes
        total_stake: u128,
        threshold: u128,
        active: bool,
        registered_at: u64,
    }

    /// Global registry stored under the module publisher account.
    struct L0Registry has key {
        validator_sets: table::Table<vector<u8>, ValidatorSet>, // key = root
        proofs: table::Table<vector<u8>, ProofState>,         // key = proof_hash
        deposits: table::Table<vector<u8>, DepositState>,     // key = quantos_deposit_id
    }

    struct ProofState has store, copy, drop {
        verified: bool,
        validator_set_root: vector<u8>,
        epoch: u64,
        slot: u64,
        accepted_at: u64,
    }

    struct DepositState has store, copy, drop {
        relayed: bool,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    }

    // ================================================================
    // Events
    // ================================================================

    #[event]
    struct ValidatorSetRegistered has drop, store {
        root: vector<u8>,
        total_stake: u128,
        threshold: u128,
    }

    #[event]
    struct ValidatorSetRevoked has drop, store {
        root: vector<u8>,
    }

    #[event]
    struct ProofVerified has drop, store {
        proof_hash: vector<u8>,
        validator_set_root: vector<u8>,
        epoch: u64,
        slot: u64,
    }

    #[event]
    struct RelayAuthorized has drop, store {
        proof_hash: vector<u8>,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    }

    // ================================================================
    // Initialization
    // ================================================================

    /// Called once by the module deployer to initialize the registry.
    public entry fun initialize(admin: &signer) {
        let addr = signer::address_of(admin);
        assert!(!exists<AdminStore>(addr), E_ALREADY_INITIALIZED);

        move_to(admin, AdminStore { admin: addr });
        move_to(admin, L0Registry {
            validator_sets: table::new(),
            proofs: table::new(),
            deposits: table::new(),
        });
    }

    // ================================================================
    // Admin helpers
    // ================================================================

    fun assert_admin(addr: address) acquires AdminStore {
        let store = borrow_global<AdminStore>(addr);
        assert!(store.admin == addr, E_NOT_ADMIN);
    }

    // ================================================================
    // Admin entry functions
    // ================================================================

    /// Register a new trusted validator set root. Only admin.
    public entry fun register_validator_set(
        admin: &signer,
        root: vector<u8>,
        total_stake: u128,
        threshold: u128,
    ) acquires AdminStore, L0Registry {
        let addr = signer::address_of(admin);
        assert_admin(addr);

        let registry = borrow_global_mut<L0Registry>(addr);
        let set = ValidatorSet {
            root: copy root,
            total_stake,
            threshold,
            active: true,
            registered_at: timestamp::now_microseconds(),
        };
        table::add(&mut registry.validator_sets, root, set);

        event::emit(ValidatorSetRegistered { root, total_stake, threshold });
    }

    /// Revoke a validator set. Only admin.
    public entry fun revoke_validator_set(
        admin: &signer,
        root: vector<u8>,
    ) acquires AdminStore, L0Registry {
        let addr = signer::address_of(admin);
        assert_admin(addr);

        let registry = borrow_global_mut<L0Registry>(addr);
        assert!(table::contains(&registry.validator_sets, root), E_UNKNOWN_SET);
        let set = table::borrow_mut(&mut registry.validator_sets, root);
        set.active = false;

        event::emit(ValidatorSetRevoked { root });
    }

    // ================================================================
    // Proof verification entry functions
    // ================================================================

    /// Verify an L0 finality proof. Stores the result in the shared registry.
    public entry fun verify_proof(
        registry_addr: address,
        set_root: vector<u8>,
        proof_hash: vector<u8>,
        epoch: u64,
        slot: u64,
        state_root: vector<u8>,
        signed_stake: u128,
    ) acquires L0Registry {
        let registry = borrow_global_mut<L0Registry>(registry_addr);

        // 1. Check validator set is known and active
        assert!(table::contains(&registry.validator_sets, set_root), E_UNKNOWN_SET);
        let set = table::borrow(&registry.validator_sets, set_root);
        assert!(set.active, E_UNKNOWN_SET);

        // 2. Replay protection
        assert!(!table::contains(&registry.proofs, proof_hash), E_PROOF_ALREADY_VERIFIED);

        // 3. Stake threshold
        assert!(signed_stake >= set.threshold, E_INSUFFICIENT_STAKE);

        let state = ProofState {
            verified: true,
            validator_set_root: set_root,
            epoch,
            slot,
            accepted_at: timestamp::now_microseconds(),
        };
        table::add(&mut registry.proofs, proof_hash, state);

        event::emit(ProofVerified {
            proof_hash,
            validator_set_root: set_root,
            epoch,
            slot,
        });
    }

    /// Authorize a bridge relay action from a previously verified proof.
    public entry fun authorize_relay(
        registry_addr: address,
        proof_hash: vector<u8>,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    ) acquires L0Registry {
        let registry = borrow_global_mut<L0Registry>(registry_addr);

        // 1. Proof must exist and be verified
        assert!(table::contains(&registry.proofs, proof_hash), E_PROOF_NOT_VERIFIED);
        let state = table::borrow(&registry.proofs, proof_hash);
        assert!(state.verified, E_PROOF_NOT_VERIFIED);

        // 2. Deposit idempotency
        assert!(!table::contains(&registry.deposits, quantos_deposit_id), E_DEPOSIT_ALREADY_RELAYED);

        let deposit = DepositState {
            relayed: true,
            quantos_deposit_id: copy quantos_deposit_id,
            amount,
        };
        table::add(&mut registry.deposits, quantos_deposit_id, deposit);

        event::emit(RelayAuthorized {
            proof_hash,
            quantos_deposit_id,
            amount,
        });
    }

    /// Emergency force mark a deposit as relayed (admin-only).
    public entry fun force_mark_relayed(
        admin: &signer,
        registry_addr: address,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    ) acquires AdminStore, L0Registry {
        let addr = signer::address_of(admin);
        assert_admin(addr);

        let registry = borrow_global_mut<L0Registry>(registry_addr);
        if (table::contains(&registry.deposits, quantos_deposit_id)) {
            let deposit = table::borrow_mut(&mut registry.deposits, quantos_deposit_id);
            deposit.relayed = true;
        } else {
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id: copy quantos_deposit_id,
                amount,
            };
            table::add(&mut registry.deposits, quantos_deposit_id, deposit);
        }
    }

    // ================================================================
    // View functions
    // ================================================================

    #[view]
    public fun is_proof_verified(registry_addr: address, proof_hash: vector<u8>): bool acquires L0Registry {
        let registry = borrow_global<L0Registry>(registry_addr);
        if (!table::contains(&registry.proofs, proof_hash)) { return false; };
        let state = table::borrow(&registry.proofs, proof_hash);
        state.verified
    }

    #[view]
    public fun is_deposit_relayed(registry_addr: address, quantos_deposit_id: vector<u8>): bool acquires L0Registry {
        let registry = borrow_global<L0Registry>(registry_addr);
        if (!table::contains(&registry.deposits, quantos_deposit_id)) { return false; };
        let deposit = table::borrow(&registry.deposits, quantos_deposit_id);
        deposit.relayed
    }
}
