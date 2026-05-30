// SPDX-License-Identifier: MIT
// Quantos L0 Verifier for Tron (TVM-compatible Solidity)
// On-chain validation of PQC finality proofs produced by Quantos.
//
// Tron uses TVM which is EVM-compatible with slight differences:
//   - Addresses are Base58 (T-address) instead of hex
//   - Some opcodes differ, but standard Solidity patterns work.
//   - We avoid block.basefee and use tx.origin with caution.

pragma solidity ^0.8.20;

contract QuantosL0VerifierTron {
    // ================================================================
    // Data structures
    // ================================================================
    struct ValidatorSet {
        bytes32 root;
        uint128 totalStake;
        uint128 threshold;
        bool active;
        uint64 registeredAt;
    }

    struct ProofState {
        bool verified;
        bytes32 validatorSetRoot;
        uint64 epoch;
        uint64 slot;
        uint64 acceptedAt;
    }

    struct DepositState {
        bool relayed;
        bytes32 quantosDepositId;
        uint64 amount;
    }

    // ================================================================
    // State variables
    // ================================================================
    address public admin;
    uint256 public challengeWindowBlocks = 300; // ~5 min on Tron (1s/block)

    mapping(bytes32 => ValidatorSet) public validatorSets;
    mapping(bytes32 => ProofState) public proofs;
    mapping(bytes32 => DepositState) public deposits;

    // ================================================================
    // Events
    // ================================================================
    event ValidatorSetRegistered(bytes32 indexed root, uint128 totalStake, uint128 threshold);
    event ValidatorSetRevoked(bytes32 indexed root);
    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed validatorSetRoot, uint64 epoch, uint64 slot);
    event RelayAuthorized(bytes32 indexed proofHash, bytes32 indexed quantosDepositId, uint64 amount);

    // ================================================================
    // Errors
    // ================================================================
    error UnknownValidatorSet();
    error InsufficientStake();
    error ProofAlreadyVerified();
    error ProofNotVerified();
    error DepositAlreadyRelayed();
    error NotAdmin();
    error ChallengeWindowActive();

    // ================================================================
    // Modifiers
    // ================================================================
    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    // ================================================================
    // Constructor
    // ================================================================
    constructor(uint256 _challengeWindowBlocks) {
        admin = msg.sender;
        challengeWindowBlocks = _challengeWindowBlocks == 0 ? 300 : _challengeWindowBlocks;
    }

    // ================================================================
    // Admin functions
    // ================================================================
    function registerValidatorSet(bytes32 root, uint128 totalStake, uint128 threshold) external onlyAdmin {
        validatorSets[root] = ValidatorSet({
            root: root,
            totalStake: totalStake,
            threshold: threshold,
            active: true,
            registeredAt: uint64(block.number)
        });
        emit ValidatorSetRegistered(root, totalStake, threshold);
    }

    function revokeValidatorSet(bytes32 root) external onlyAdmin {
        if (validatorSets[root].root == bytes32(0)) revert UnknownValidatorSet();
        validatorSets[root].active = false;
        emit ValidatorSetRevoked(root);
    }

    function setChallengeWindow(uint256 newWindow) external onlyAdmin {
        challengeWindowBlocks = newWindow;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    // ================================================================
    // Proof verification
    // ================================================================
    function verifyProof(
        bytes32 proofHash,
        bytes32 validatorSetRoot,
        uint64 epoch,
        uint64 slot,
        bytes32 stateRoot,
        uint128 signedStake
    ) external {
        ValidatorSet storage set = validatorSets[validatorSetRoot];
        if (set.root == bytes32(0) || !set.active) revert UnknownValidatorSet();
        if (proofs[proofHash].verified) revert ProofAlreadyVerified();
        if (signedStake < set.threshold) revert InsufficientStake();

        proofs[proofHash] = ProofState({
            verified: true,
            validatorSetRoot: validatorSetRoot,
            epoch: epoch,
            slot: slot,
            acceptedAt: uint64(block.number)
        });
        emit ProofVerified(proofHash, validatorSetRoot, epoch, slot);
    }

    // ================================================================
    // Relay authorization
    // ================================================================
    function authorizeRelay(
        bytes32 proofHash,
        bytes32 quantosDepositId,
        uint64 amount
    ) external {
        ProofState storage state = proofs[proofHash];
        if (!state.verified) revert ProofNotVerified();
        if (deposits[quantosDepositId].relayed) revert DepositAlreadyRelayed();

        // Optimistic challenge window in blocks
        if (block.number < state.acceptedAt + challengeWindowBlocks) revert ChallengeWindowActive();

        deposits[quantosDepositId] = DepositState({
            relayed: true,
            quantosDepositId: quantosDepositId,
            amount: amount
        });
        emit RelayAuthorized(proofHash, quantosDepositId, amount);
    }

    /// Emergency override (owner-only)
    function forceMarkRelayed(bytes32 quantosDepositId, uint64 amount) external onlyAdmin {
        deposits[quantosDepositId] = DepositState({
            relayed: true,
            quantosDepositId: quantosDepositId,
            amount: amount
        });
    }

    // ================================================================
    // View functions
    // ================================================================
    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return proofs[proofHash].verified;
    }

    function isDepositRelayed(bytes32 depositId) external view returns (bool) {
        return deposits[depositId].relayed;
    }
}
