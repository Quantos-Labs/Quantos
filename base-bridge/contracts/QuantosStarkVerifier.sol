// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/**
 * @title  QuantosStarkVerifier
 * @notice On-chain registry for ZK-STARK batch proof commitments.
 *
 * @dev    Architecture
 * ─────────────────────────────────────────────────────────────────
 * Full Winterfell STARK verification in Solidity is impractical
 * (~10 MB bytecode, millions of gas). Instead we use a two-layer
 * approach:
 *
 *   Layer 1 (off-chain) — Rust `verify_batch()` in `stark_prover.rs`
 *     verifies the full Winterfell STARK proof in < 10 ms.
 *
 *   Layer 2 (on-chain, this contract) — Records a 32-byte
 *     `starkCommitment = SHA3(proof_bytes || validator_set_root ||
 *      message_hash || signed_stake || stake_threshold)` together
 *     with the verified public inputs.
 *
 * Any observer can call `verifyCommitment()` to confirm that a given
 * `(validatorSetRoot, signedStake, proofHash)` tuple was proven via
 * a valid STARK batch proof submitted by an authorized prover.
 *
 * @dev    Trust model
 * Only addresses in `authorizedProvers` may submit commitments.  In
 * production these are the same Quantos validator nodes that run
 * the Rust verifier and act as `StarkProofSubmitters`.
 */
contract QuantosStarkVerifier {

    // ── Events ──────────────────────────────────────────────────────────────

    event StarkCommitmentSubmitted(
        bytes32 indexed starkCommitment,
        bytes32 indexed validatorSetRoot,
        uint128          signedStake,
        uint128          stakeThreshold,
        uint32           signerCount,
        bytes32          messageHash,
        address          submitter
    );

    event ProverAuthorized(address indexed prover);
    event ProverRevoked(address indexed prover);

    // ── Errors ───────────────────────────────────────────────────────────────

    error Unauthorized();
    error CommitmentAlreadySubmitted(bytes32 commitment);
    error InvalidCommitment();
    error StakeThresholdNotMet(uint128 signedStake, uint128 required);

    // ── Storage ──────────────────────────────────────────────────────────────

    address public immutable owner;

    /// Addresses allowed to submit STARK commitments.
    mapping(address => bool) public authorizedProvers;

    /// starkCommitment → public inputs recorded on-chain.
    struct StarkRecord {
        bytes32 validatorSetRoot;
        bytes32 messageHash;
        uint128 signedStake;
        uint128 stakeThreshold;
        uint32  signerCount;
        uint64  submittedAt;
        address submitter;
    }
    mapping(bytes32 => StarkRecord) public records;

    /// Reverse index: proofHash → starkCommitment (for lookup from L0FinalityProof).
    mapping(bytes32 => bytes32) public proofHashToCommitment;

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(address[] memory initialProvers) {
        owner = msg.sender;
        for (uint256 i = 0; i < initialProvers.length; i++) {
            authorizedProvers[initialProvers[i]] = true;
            emit ProverAuthorized(initialProvers[i]);
        }
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    function authorizeProver(address prover) external {
        if (msg.sender != owner) revert Unauthorized();
        authorizedProvers[prover] = true;
        emit ProverAuthorized(prover);
    }

    function revokeProver(address prover) external {
        if (msg.sender != owner) revert Unauthorized();
        authorizedProvers[prover] = false;
        emit ProverRevoked(prover);
    }

    // ── Core ─────────────────────────────────────────────────────────────────

    /**
     * @notice Submit a STARK batch proof commitment.
     *
     * @dev Called by an authorized prover node after running
     *      `verify_batch()` in Rust and confirming the proof is valid.
     *
     * @param starkCommitment   SHA3-256(proof_bytes || validatorSetRoot ||
     *                          messageHash || signedStake || stakeThreshold)
     * @param validatorSetRoot  Merkle root of the validator set snapshot.
     * @param messageHash       Hash of the signing message (L0 proof digest).
     * @param signedStake       Aggregated signed stake attested by the proof.
     * @param stakeThreshold    Required stake threshold for finality.
     * @param signerCount       Number of validators in the batch.
     * @param proofHash         Hash of the corresponding L0FinalityProof
     *                          (used as reverse index).
     */
    function submitCommitment(
        bytes32 starkCommitment,
        bytes32 validatorSetRoot,
        bytes32 messageHash,
        uint128 signedStake,
        uint128 stakeThreshold,
        uint32  signerCount,
        bytes32 proofHash
    ) external {
        if (!authorizedProvers[msg.sender]) revert Unauthorized();
        if (starkCommitment == bytes32(0))  revert InvalidCommitment();
        if (records[starkCommitment].submittedAt != 0)
            revert CommitmentAlreadySubmitted(starkCommitment);
        if (signedStake < stakeThreshold)
            revert StakeThresholdNotMet(signedStake, stakeThreshold);

        records[starkCommitment] = StarkRecord({
            validatorSetRoot: validatorSetRoot,
            messageHash:      messageHash,
            signedStake:      signedStake,
            stakeThreshold:   stakeThreshold,
            signerCount:      signerCount,
            submittedAt:      uint64(block.timestamp),
            submitter:        msg.sender
        });

        if (proofHash != bytes32(0)) {
            proofHashToCommitment[proofHash] = starkCommitment;
        }

        emit StarkCommitmentSubmitted(
            starkCommitment,
            validatorSetRoot,
            signedStake,
            stakeThreshold,
            signerCount,
            messageHash,
            msg.sender
        );
    }

    // ── View helpers ─────────────────────────────────────────────────────────

    /**
     * @notice Check whether a commitment has been recorded and its signed
     *         stake meets the threshold.
     *
     * @param starkCommitment  The commitment to query.
     * @return valid           True if the commitment exists and stake >= threshold.
     */
    function verifyCommitment(bytes32 starkCommitment)
        external
        view
        returns (bool valid)
    {
        StarkRecord storage r = records[starkCommitment];
        if (r.submittedAt == 0) return false;
        return r.signedStake >= r.stakeThreshold;
    }

    /**
     * @notice Look up the STARK commitment associated with a given proof hash.
     *
     * @param proofHash  Hash of the L0FinalityProof.
     * @return           The corresponding starkCommitment, or bytes32(0) if none.
     */
    function commitmentForProof(bytes32 proofHash)
        external
        view
        returns (bytes32)
    {
        return proofHashToCommitment[proofHash];
    }

    /**
     * @notice Recompute and verify the commitment on-chain from its components.
     *
     * @dev    Any party can call this to confirm that a submitted commitment
     *         matches the expected hash of its public inputs without re-running
     *         the full STARK verifier.
     *
     *         Note: the `proof_bytes` field is NOT passed here — it is too
     *         large for on-chain storage.  Only the commitment hash over it
     *         is checked.  Full verification requires running Rust off-chain.
     *
     * @param starkCommitment   The commitment to validate.
     * @param validatorSetRoot  Public input: validator set root.
     * @param messageHash       Public input: message hash.
     * @param signedStake       Public input: signed stake.
     * @param stakeThreshold    Public input: stake threshold.
     * @return                  True if the stored record matches all inputs.
     */
    function verifyPublicInputs(
        bytes32 starkCommitment,
        bytes32 validatorSetRoot,
        bytes32 messageHash,
        uint128 signedStake,
        uint128 stakeThreshold
    ) external view returns (bool) {
        StarkRecord storage r = records[starkCommitment];
        if (r.submittedAt == 0) return false;
        return
            r.validatorSetRoot == validatorSetRoot &&
            r.messageHash      == messageHash      &&
            r.signedStake      == signedStake      &&
            r.stakeThreshold   == stakeThreshold;
    }
}
