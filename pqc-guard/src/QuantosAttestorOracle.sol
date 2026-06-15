// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAttestorSetOracle} from "./interfaces/IAttestorSetOracle.sol";

/// @notice Minimal surface of the existing Quantos L0 proof verifier. The real
/// `QuantosL0Verifier` (in base-bridge) verifies a PQC finality proof off-chain
/// signatures + stake threshold and records its hash here.
interface IL0ProofRegistry {
    function isProofVerified(bytes32 proofHash) external view returns (bool);
}

/// @title QuantosAttestorOracle
/// @notice Holds the latest FINALIZED PQC-Guard attestor-set root, sourced from
/// Quantos L1 via an L0 finality proof. This is the concrete embodiment of
/// "using PQC-Guard = using Quantos": the attestor set (who can attest) is the
/// QTS-staked Quantos validator set, finalized by Quantos consensus.
///
/// ## Update path (Phase 1 POC)
/// A relayer:
///   1. Obtains an `L0FinalityProof` from Quantos whose validator set signed off
///      on the current attestor-set root for `epoch`.
///   2. Submits it to `QuantosL0Verifier` (PQC + stake threshold checked) which
///      records `isProofVerified(proofHash) == true`.
///   3. Calls {updateAttestorSet} here, referencing that verified proof.
///
/// // AUDIT REQUIRED — POC trust note: this oracle currently trusts the relayer
/// to pass the attestor-set root that matches the referenced proof. In the
/// production design the root is bound INTO the proof (header field or via a
/// Quantos state-inclusion proof against `state_root`) and re-derived here, so
/// no relayer trust is needed. The interface to consumers does not change.
contract QuantosAttestorOracle is IAttestorSetOracle {
    IL0ProofRegistry public immutable l0Verifier;
    address public owner;

    bytes32 private _attestorSetRoot;
    uint64 private _attestorEpoch;
    uint256 private _threshold;

    /// @notice Records which L0 proofs have already been consumed for an update.
    mapping(bytes32 => bool) public consumedProof;

    event AttestorSetUpdated(bytes32 indexed root, uint64 indexed epoch, uint256 threshold, bytes32 l0ProofHash);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

    error NotOwner();
    error StaleEpoch(uint64 provided, uint64 current);
    error ProofNotVerified(bytes32 proofHash);
    error ProofAlreadyConsumed(bytes32 proofHash);
    error ZeroRoot();
    error ZeroThreshold();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IL0ProofRegistry _l0Verifier, address _owner) {
        l0Verifier = _l0Verifier;
        owner = _owner;
    }

    /// @notice Update the finalized attestor set from a verified L0 proof.
    /// @param root        New attestor-set Merkle root (from Quantos).
    /// @param epoch       Quantos epoch (must strictly increase).
    /// @param newThreshold M-of-N quorum decided by Quantos governance.
    /// @param l0ProofHash A proof hash already verified by the L0 verifier.
    function updateAttestorSet(
        bytes32 root,
        uint64 epoch,
        uint256 newThreshold,
        bytes32 l0ProofHash
    ) external onlyOwner {
        if (root == bytes32(0)) revert ZeroRoot();
        if (newThreshold == 0) revert ZeroThreshold();
        if (epoch <= _attestorEpoch && _attestorEpoch != 0) revert StaleEpoch(epoch, _attestorEpoch);
        if (!l0Verifier.isProofVerified(l0ProofHash)) revert ProofNotVerified(l0ProofHash);
        if (consumedProof[l0ProofHash]) revert ProofAlreadyConsumed(l0ProofHash);

        consumedProof[l0ProofHash] = true;
        _attestorSetRoot = root;
        _attestorEpoch = epoch;
        _threshold = newThreshold;

        emit AttestorSetUpdated(root, epoch, newThreshold, l0ProofHash);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    // ── IAttestorSetOracle ──

    function attestorSetRoot() external view returns (bytes32) {
        return _attestorSetRoot;
    }

    function attestorEpoch() external view returns (uint64) {
        return _attestorEpoch;
    }

    function threshold() external view returns (uint256) {
        return _threshold;
    }
}
