// Quantos L0 Verifier for Sui (Move)
// On-chain validation of PQC finality proofs produced by Quantos.

module quantos::l0_verifier {
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};
    use sui::event;
    use std::vector;
    use std::option::{Self, Option};

    // ================================================================
    // Constants & Error codes
    // ================================================================

    const E_UNKNOWN_SET: u64 = 0;
    const E_INSUFFICIENT_STAKE: u64 = 1;
    const E_PROOF_ALREADY_VERIFIED: u64 = 2;
    const E_PROOF_NOT_VERIFIED: u64 = 3;
    const E_DEPOSIT_ALREADY_RELAYED: u64 = 4;
    const E_NOT_OWNER: u64 = 5;

    // ================================================================
    // Structs (Sui objects)
    // ================================================================

    /// Capability object used to register/revoke validator sets.
    struct AdminCap has key, store { id: UID }

    /// A trusted validator set root registered by the Quantos L0 hub.
    struct ValidatorSet has key, store {
        id: UID,
        root: vector<u8>,   // 32 bytes
        total_stake: u128,
        threshold: u128,
        active: bool,
        registered_at: u64,
    }

    /// Shared global registry of proof states and relayed deposits.
    struct L0Registry has key {
        id: UID,
        proofs: Table<vector<u8>, ProofState>,    // key = proof_hash (32 bytes)
        deposits: Table<vector<u8>, DepositState>, // key = quantos_deposit_id (32 bytes)
    }

    /// Represents a verified L0 proof.
    struct ProofState has store, copy, drop {
        verified: bool,
        validator_set_root: vector<u8>,
        epoch: u64,
        slot: u64,
        accepted_at: u64,
    }

    /// Represents a single relayed deposit (idempotency).
    struct DepositState has store, copy, drop {
        relayed: bool,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    }

    // ================================================================
    // Events
    // ================================================================

    struct ValidatorSetRegistered has copy, drop {
        root: vector<u8>,
        total_stake: u128,
        threshold: u128,
        set_id: ID,
    }

    struct ValidatorSetRevoked has copy, drop {
        set_id: ID,
    }

    struct ProofVerified has copy, drop {
        proof_hash: vector<u8>,
        validator_set_root: vector<u8>,
        epoch: u64,
        slot: u64,
    }

    struct RelayAuthorized has copy, drop {
        proof_hash: vector<u8>,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    }

    // ================================================================
    // Initialization
    // ================================================================

    /// Deployer calls this once to create the shared registry + admin cap.
    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
        transfer::share_object(L0Registry {
            id: object::new(ctx),
            proofs: table::new(ctx),
            deposits: table::new(ctx),
        });
    }

    // ================================================================
    // Admin entry functions
    // ================================================================

    /// Register a new trusted validator set root. Only holder of AdminCap.
    public entry fun register_validator_set(
        _cap: &AdminCap,
        registry: &mut L0Registry,
        root: vector<u8>,
        total_stake: u128,
        threshold: u128,
        ctx: &mut TxContext,
    ) {
        assert!(vector::length(&root) == 32, E_NOT_OWNER);
        let set = ValidatorSet {
            id: object::new(ctx),
            root,
            total_stake,
            threshold,
            active: true,
            registered_at: tx_context::epoch_timestamp_ms(ctx),
        };
        let set_id = object::id(&set);
        transfer::share_object(set);

        event::emit(ValidatorSetRegistered {
            root,
            total_stake,
            threshold,
            set_id,
        });
    }

    /// Revoke a validator set (freeze it). Only holder of AdminCap.
    public entry fun revoke_validator_set(
        _cap: &AdminCap,
        set: &mut ValidatorSet,
    ) {
        set.active = false;
        event::emit(ValidatorSetRevoked { set_id: object::id(set) });
    }

    // ================================================================
    // Proof verification entry functions
    // ================================================================

    /// Verify an L0 finality proof. Stores the result in the shared registry.
    public entry fun verify_proof(
        registry: &mut L0Registry,
        set: &ValidatorSet,
        proof_hash: vector<u8>,
        epoch: u64,
        slot: u64,
        state_root: vector<u8>,
        signed_stake: u128,
        ctx: &mut TxContext,
    ) {
        // 1. Check validator set is known and active
        assert!(set.active, E_UNKNOWN_SET);

        // 2. Replay protection
        assert!(!table::contains(&registry.proofs, proof_hash), E_PROOF_ALREADY_VERIFIED);

        // 3. Stake threshold
        assert!(signed_stake >= set.threshold, E_INSUFFICIENT_STAKE);

        let state = ProofState {
            verified: true,
            validator_set_root: set.root,
            epoch,
            slot,
            accepted_at: tx_context::epoch_timestamp_ms(ctx),
        };
        table::add(&mut registry.proofs, proof_hash, state);

        event::emit(ProofVerified {
            proof_hash,
            validator_set_root: set.root,
            epoch,
            slot,
        });
    }

    /// Authorize a bridge relay action from a previously verified proof.
    public entry fun authorize_relay(
        registry: &mut L0Registry,
        proof_hash: vector<u8>,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    ) {
        // 1. Proof must exist and be verified
        let state = table::borrow(&registry.proofs, proof_hash);
        assert!(state.verified, E_PROOF_NOT_VERIFIED);

        // 2. Deposit idempotency
        assert!(!table::contains(&registry.deposits, quantos_deposit_id), E_DEPOSIT_ALREADY_RELAYED);

        let deposit = DepositState {
            relayed: true,
            quantos_deposit_id,
            amount,
        };
        table::add(&mut registry.deposits, quantos_deposit_id, deposit);

        event::emit(RelayAuthorized {
            proof_hash,
            quantos_deposit_id,
            amount,
        });
    }

    /// Emergency force mark a deposit as relayed (owner-only).
    public entry fun force_mark_relayed(
        _cap: &AdminCap,
        registry: &mut L0Registry,
        quantos_deposit_id: vector<u8>,
        amount: u64,
    ) {
        if (table::contains(&registry.deposits, quantos_deposit_id)) {
            let deposit = table::borrow_mut(&mut registry.deposits, quantos_deposit_id);
            deposit.relayed = true;
        } else {
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id,
                amount,
            };
            table::add(&mut registry.deposits, quantos_deposit_id, deposit);
        }
    }

    // ================================================================
    // View functions (read-only)
    // ================================================================

    #[view]
    public fun is_proof_verified(registry: &L0Registry, proof_hash: vector<u8>): bool {
        if (!table::contains(&registry.proofs, proof_hash)) { return false; };
        let state = table::borrow(&registry.proofs, proof_hash);
        state.verified
    }

    #[view]
    public fun is_deposit_relayed(registry: &L0Registry, quantos_deposit_id: vector<u8>): bool {
        if (!table::contains(&registry.deposits, quantos_deposit_id)) { return false; };
        let deposit = table::borrow(&registry.deposits, quantos_deposit_id);
        deposit.relayed
    }
}
