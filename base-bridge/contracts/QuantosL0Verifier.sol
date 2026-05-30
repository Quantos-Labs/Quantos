// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title QuantosL0Verifier
/// @notice On-chain verifier for Quantos L0 PQC finality proofs.
/// @dev This contract stores trusted validator set roots and verifies that
/// a submitted L0FinalityProof references a known set with sufficient stake.
/// Full PQC signature verification (Falcon-512 / Dilithium-3) is performed
/// off-chain by the relayer; this contract validates structure, replay
/// protection, and stake threshold for the attested proof.
contract QuantosL0Verifier is Ownable2Step {
    /// @notice A trusted validator set root that can sign proofs
    struct ValidatorSet {
        uint128 totalStake;
        uint128 threshold;
        bool active;
        uint64 registeredAt;
    }

    /// @notice Emitted when a new validator set root is registered
    event ValidatorSetRegistered(bytes32 indexed root, uint128 totalStake, uint128 threshold);
    /// @notice Emitted when a validator set is revoked
    event ValidatorSetRevoked(bytes32 indexed root);
    /// @notice Emitted when an L0 proof is successfully verified
    event ProofVerified(bytes32 indexed proofHash, bytes32 indexed validatorSetRoot, uint64 epoch, uint64 slot);
    /// @notice Emitted when a relay action is authorized from a verified proof
    event RelayAuthorized(bytes32 indexed proofHash, bytes32 indexed quantosDepositId, uint256 amount);
    /// @notice Emitted when an external block is finalized with PQC proof
    event BlockFinalized(uint256 indexed blockNumber, bytes32 indexed blockHash, bytes32 indexed proofHash);

    /// @notice Mapping of trusted validator set roots
    mapping(bytes32 => ValidatorSet) public validatorSets;
    /// @notice Mapping of already-verified proof hashes (replay protection)
    mapping(bytes32 => bool) public verifiedProofs;
    /// @notice Mapping of already-relayed deposit IDs (idempotency)
    mapping(bytes32 => bool) public relayedDeposits;
    /// @notice Mapping of finalized block numbers to their PQC-certified block hashes
    mapping(uint256 => bytes32) public finalizedBlocks;
    /// @notice Mapping of finalized block hashes to their proof hashes
    mapping(bytes32 => bytes32) public blockProofs;

    /// @notice Challenge window in seconds for optimistic proof acceptance
    uint256 public challengeWindowSeconds = 300; // 5 minutes default
    /// @notice Time at which a proof was accepted (for challenge window)
    mapping(bytes32 => uint256) public proofAcceptedAt;

    error UnknownValidatorSet();
    error InsufficientStake();
    error ProofAlreadyVerified();
    error DepositAlreadyRelayed();
    error ChallengeWindowActive();
    error ChallengeWindowExpired();
    error InvalidProofFormat();
    error ZeroValue();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Register a new trusted validator set root. Only owner.
    /// @param root The validator set root hash
    /// @param totalStake Total stake represented by this set
    /// @param threshold Minimum stake required for finality
    function registerValidatorSet(bytes32 root, uint128 totalStake, uint128 threshold) external onlyOwner {
        if (root == bytes32(0)) revert InvalidProofFormat();
        validatorSets[root] = ValidatorSet({
            totalStake: totalStake,
            threshold: threshold,
            active: true,
            registeredAt: uint64(block.timestamp)
        });
        emit ValidatorSetRegistered(root, totalStake, threshold);
    }

    /// @notice Revoke a validator set root. Only owner.
    function revokeValidatorSet(bytes32 root) external onlyOwner {
        validatorSets[root].active = false;
        emit ValidatorSetRevoked(root);
    }

    /// @notice Update challenge window. Only owner.
    function setChallengeWindow(uint256 seconds_) external onlyOwner {
        challengeWindowSeconds = seconds_;
    }

    /// @notice Verify an L0 finality proof. Returns the proof hash if valid.
    /// @dev The relayer must have already verified PQC signatures off-chain.
    /// This contract checks: (1) known validator set, (2) sufficient stake,
    /// (3) not already verified, (4) proof format sanity.
    function verifyProof(
        bytes32 proofHash,
        bytes32 validatorSetRoot,
        uint128 signedStake,
        uint64 epoch,
        uint64 slot,
        bytes32 stateRoot
    ) external returns (bool) {
        if (proofHash == bytes32(0)) revert InvalidProofFormat();
        if (verifiedProofs[proofHash]) revert ProofAlreadyVerified();

        ValidatorSet storage vs = validatorSets[validatorSetRoot];
        if (!vs.active) revert UnknownValidatorSet();
        if (signedStake < vs.threshold) revert InsufficientStake();

        verifiedProofs[proofHash] = true;
        proofAcceptedAt[proofHash] = block.timestamp;

        emit ProofVerified(proofHash, validatorSetRoot, epoch, slot);
        return true;
    }

    /// @notice Authorize a bridge relay action from a previously verified proof.
    /// @param proofHash The hash of the already-verified L0 proof
    /// @param quantosDepositId Unique deposit identifier on Quantos side
    /// @param amount Amount to be relayed
    /// @return true if relay is authorized
    function authorizeRelay(
        bytes32 proofHash,
        bytes32 quantosDepositId,
        uint256 amount
    ) external returns (bool) {
        if (amount == 0) revert ZeroValue();
        if (!verifiedProofs[proofHash]) revert InvalidProofFormat();
        if (relayedDeposits[quantosDepositId]) revert DepositAlreadyRelayed();

        uint256 acceptedAt = proofAcceptedAt[proofHash];
        if (acceptedAt == 0) revert InvalidProofFormat();
        if (block.timestamp < acceptedAt + challengeWindowSeconds) {
            // Challenge window is still active — require an additional
            // confirmation signature from a Quantos validator (not implemented
            // in v1; this is a placeholder for optimistic challenge design).
            revert ChallengeWindowActive();
        }

        relayedDeposits[quantosDepositId] = true;
        emit RelayAuthorized(proofHash, quantosDepositId, amount);
        return true;
    }

    /// @notice Emergency override to mark a deposit as relayed. Only owner.
    function forceMarkRelayed(bytes32 quantosDepositId) external onlyOwner {
        relayedDeposits[quantosDepositId] = true;
    }

    /// @notice Check if a proof hash has been verified.
    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return verifiedProofs[proofHash];
    }

    /// @notice Check if a deposit has already been relayed.
    function isDepositRelayed(bytes32 quantosDepositId) external view returns (bool) {
        return relayedDeposits[quantosDepositId];
    }

    /// @notice Finalize an external block with Quantos L0 PQC proof.
    /// @dev This enables this chain to anchor its finality on Quantos.
    /// The proof must have been verified by Quantos validators with PQC signatures.
    /// @param blockNumber The block number being finalized
    /// @param blockHash The block hash being finalized
    /// @param proofHash The hash of the Quantos L0 proof
    /// @param validatorSetRoot The validator set that signed the proof
    /// @param signedStake The total stake that signed the proof
    /// @param stateRoot The state root at this block
    /// @return true if finalization succeeded
    function finalizeBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 proofHash,
        bytes32 validatorSetRoot,
        uint128 signedStake,
        bytes32 stateRoot
    ) external returns (bool) {
        if (proofHash == bytes32(0) || blockHash == bytes32(0)) revert InvalidProofFormat();
        if (verifiedProofs[proofHash]) revert ProofAlreadyVerified();

        ValidatorSet storage vs = validatorSets[validatorSetRoot];
        if (!vs.active) revert UnknownValidatorSet();
        if (signedStake < vs.threshold) revert InsufficientStake();

        // Mark proof as verified
        verifiedProofs[proofHash] = true;
        proofAcceptedAt[proofHash] = block.timestamp;

        // Record finalized block
        finalizedBlocks[blockNumber] = blockHash;
        blockProofs[blockHash] = proofHash;

        emit ProofVerified(proofHash, validatorSetRoot, uint64(blockNumber), 0);
        emit BlockFinalized(blockNumber, blockHash, proofHash);
        return true;
    }

    /// @notice Check if a block has been finalized with PQC proof.
    function isBlockFinalized(uint256 blockNumber) external view returns (bool) {
        return finalizedBlocks[blockNumber] != bytes32(0);
    }

    /// @notice Get the finalized block hash for a given block number.
    function getFinalizedBlockHash(uint256 blockNumber) external view returns (bytes32) {
        return finalizedBlocks[blockNumber];
    }

    /// @notice Get the proof hash that finalized a given block.
    function getBlockProof(bytes32 blockHash) external view returns (bytes32) {
        return blockProofs[blockHash];
    }
}
