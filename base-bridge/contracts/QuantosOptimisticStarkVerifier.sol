// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BatchAggVerifier} from "./BatchAggVerifier.sol";

/**
 * @title  QuantosOptimisticStarkVerifier
 * @notice On-chain optimistic STARK verifier with cryptographic fall-back.
 *
 * @dev    Architecture — Verify-on-Demand (two-tier)
 * ─────────────────────────────────────────────────────────────────
 * Tier 1 (Optimistic) : an authorized submitter posts a 32-byte
 *   `starkCommitment` together with a slashable bond.  The
 *   commitment is treated as valid for the duration of the
 *   challenge window.
 *
 * Tier 2 (Cryptographic) : any watcher can challenge the
 *   commitment during the window by posting a matching challenge
 *   bond.  The dispute is then resolved by running the full
 *   Winterfell STARK verification on-chain via
 *   `BatchAggVerifier.verify()`.
 *
 *   * If the proof verifies → submitter was honest, challenger is
 *     slashed, submitter receives both bonds.
 *   * If the proof fails → challenger was correct, submitter is
 *     slashed, challenger receives both bonds.
 *
 * Security assumptions:
 *   - 1-of-N honest watchers (any single honest party can trigger
 *     Tier 2 within the challenge window).
 *   - The bond amount exceeds the maximum extractable value of a
 *     false commitment, otherwise rational actors will not watch.
 */
contract QuantosOptimisticStarkVerifier is BatchAggVerifier, Ownable {

    // ── Events ──────────────────────────────────────────────────────────────

    event CommitmentSubmitted(
        bytes32 indexed starkCommitment,
        bytes32 indexed validatorSetRoot,
        uint128 signedStake,
        address indexed submitter,
        uint256 bond
    );

    event CommitmentChallenged(
        bytes32 indexed starkCommitment,
        address indexed challenger,
        uint256 bond
    );

    event ChallengeResolved(
        bytes32 indexed starkCommitment,
        bool proofValid,
        address indexed winner,
        uint256 payout
    );

    event BondWithdrawn(
        bytes32 indexed starkCommitment,
        address indexed recipient,
        uint256 amount
    );

    event BondAmountUpdated(uint256 newBond);
    event ChallengeWindowUpdated(uint256 newWindow);

    // ── Errors ────────────────────────────────────────────────────────────

    error Unauthorized();
    error InvalidCommitment();
    error CommitmentAlreadySubmitted(bytes32 commitment);
    error ChallengeWindowExpired();
    error ChallengeWindowStillActive();
    error AlreadyChallenged();
    error AlreadyResolved();
    error NotChallenged();
    error NotSubmitter();
    error InsufficientBond(uint256 sent, uint256 required);
    error NoBondToWithdraw();
    error TransferFailed();
    error StakeThresholdNotMet(uint128 signedStake, uint128 required);

    // ── Storage ───────────────────────────────────────────────────────────

    /// @notice Bond required to submit or challenge a commitment.
    uint256 public bondAmount;

    /// @notice Challenge window in seconds.
    uint256 public challengeWindowSeconds;

    /// @notice Record of a submitted commitment.
    struct CommitmentRecord {
        bytes32 validatorSetRoot;
        bytes32 messageHash;
        uint128 signedStake;
        uint128 stakeThreshold;
        uint32 signerCount;
        uint64 submittedAt;
        address submitter;
        uint256 bond;          // submitter bond
        bool challenged;
        address challenger;
        uint256 challengeBond; // challenger bond
        bool resolved;
        bool valid;            // outcome of challenge resolution
    }

    mapping(bytes32 => CommitmentRecord) public records;

    /// @notice Reverse index: proofHash -> starkCommitment.
    mapping(bytes32 => bytes32) public proofHashToCommitment;

    // ── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address initialOwner,
        uint256 initialBondAmount,
        uint256 initialChallengeWindow
    ) Ownable(initialOwner) {
        bondAmount = initialBondAmount;
        challengeWindowSeconds = initialChallengeWindow;
    }

    // ── Admin ─────────────────────────────────────────────────────────────

    function setBondAmount(uint256 newAmount) external onlyOwner {
        bondAmount = newAmount;
        emit BondAmountUpdated(newAmount);
    }

    function setChallengeWindow(uint256 newWindow) external onlyOwner {
        challengeWindowSeconds = newWindow;
        emit ChallengeWindowUpdated(newWindow);
    }

    // ── Tier 1 : Optimistic submission ────────────────────────────────────

    /**
     * @notice Submit a STARK batch proof commitment under a slashable bond.
     *
     * @dev  The commitment remains in an optimistic state until either:
     *         (a) the challenge window expires without a challenge, or
     *         (b) a challenge is posted and resolved via Tier 2.
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
        uint32 signerCount,
        bytes32 proofHash
    ) external payable {
        if (msg.value < bondAmount) {
            revert InsufficientBond(msg.value, bondAmount);
        }
        if (starkCommitment == bytes32(0)) revert InvalidCommitment();
        if (records[starkCommitment].submittedAt != 0) {
            revert CommitmentAlreadySubmitted(starkCommitment);
        }
        if (signedStake < stakeThreshold) {
            revert StakeThresholdNotMet(signedStake, stakeThreshold);
        }

        records[starkCommitment] = CommitmentRecord({
            validatorSetRoot: validatorSetRoot,
            messageHash: messageHash,
            signedStake: signedStake,
            stakeThreshold: stakeThreshold,
            signerCount: signerCount,
            submittedAt: uint64(block.timestamp),
            submitter: msg.sender,
            bond: msg.value,
            challenged: false,
            challenger: address(0),
            challengeBond: 0,
            resolved: false,
            valid: false
        });

        if (proofHash != bytes32(0)) {
            proofHashToCommitment[proofHash] = starkCommitment;
        }

        emit CommitmentSubmitted(
            starkCommitment,
            validatorSetRoot,
            signedStake,
            msg.sender,
            msg.value
        );
    }

    /**
     * @notice Withdraw the submitter bond after the challenge window
     *         has expired without any challenge.
     */
    function withdrawBond(bytes32 starkCommitment) external {
        CommitmentRecord storage r = records[starkCommitment];
        if (msg.sender != r.submitter) revert NotSubmitter();
        if (r.challenged) revert AlreadyChallenged();
        if (block.timestamp < r.submittedAt + challengeWindowSeconds) {
            revert ChallengeWindowStillActive();
        }
        if (r.bond == 0) revert NoBondToWithdraw();

        uint256 amount = r.bond;
        r.bond = 0;

        (bool success, ) = payable(r.submitter).call{value: amount}("");
        if (!success) revert TransferFailed();

        emit BondWithdrawn(starkCommitment, r.submitter, amount);
    }

    // ── Tier 2 : Challenge & resolution ───────────────────────────────────

    /**
     * @notice Challenge an optimistic commitment during the challenge window.
     *
     * @dev  Anyone (permissionless) can challenge by matching the bond amount.
     *       The challenger must be prepared to provide the full STARK proof
     *       if the submitter does not resolve the dispute themselves.
     */
    function challengeCommitment(bytes32 starkCommitment) external payable {
        CommitmentRecord storage r = records[starkCommitment];
        if (r.submittedAt == 0) revert InvalidCommitment();
        if (r.challenged) revert AlreadyChallenged();
        if (r.resolved) revert AlreadyResolved();
        if (block.timestamp >= r.submittedAt + challengeWindowSeconds) {
            revert ChallengeWindowExpired();
        }
        if (msg.value < bondAmount) {
            revert InsufficientBond(msg.value, bondAmount);
        }

        r.challenged = true;
        r.challenger = msg.sender;
        r.challengeBond = msg.value;

        emit CommitmentChallenged(starkCommitment, msg.sender, msg.value);
    }

    /**
     * @notice Resolve a challenged commitment by running the full STARK
     *         verification on-chain.
     *
     * @dev  The `proof` calldata contains the complete Winterfell STARK
     *       proof (trace commitments, query openings, FRI layers).
     *       Gas cost is high (~200k–1M gas depending on proof size) but
     *       this path is only exercised when a dispute actually occurs.
     *
     * @param starkCommitment  The commitment being challenged.
     * @param proof            Full STARK proof for `BatchAggVerifier`.
     */
    function resolveChallenge(
        bytes32 starkCommitment,
        StarkProof calldata proof
    ) external {
        CommitmentRecord storage r = records[starkCommitment];
        if (!r.challenged) revert NotChallenged();
        if (r.resolved) revert AlreadyResolved();

        // Tier 2 : cryptographic verification
        bool proofValid = verify(proof);

        r.resolved = true;
        r.valid = proofValid;

        uint256 totalPayout = r.bond + r.challengeBond;

        if (proofValid) {
            // Submitter was honest → challenger slashed, submitter wins both bonds.
            r.bond = 0;
            r.challengeBond = 0;
            (bool success, ) = payable(r.submitter).call{value: totalPayout}("");
            if (!success) revert TransferFailed();

            emit ChallengeResolved(starkCommitment, true, r.submitter, totalPayout);
        } else {
            // Challenger was correct → submitter slashed, challenger wins both bonds.
            address winner = r.challenger;
            r.bond = 0;
            r.challengeBond = 0;
            (bool success, ) = payable(winner).call{value: totalPayout}("");
            if (!success) revert TransferFailed();

            emit ChallengeResolved(starkCommitment, false, winner, totalPayout);
        }
    }

    // ── View helpers ──────────────────────────────────────────────────────

    /**
     * @notice Check whether a commitment exists and is in an optimistic
     *         valid state (submitted, stake threshold met, not proven invalid).
     */
    function isCommitmentValid(bytes32 starkCommitment)
        external
        view
        returns (bool)
    {
        CommitmentRecord storage r = records[starkCommitment];
        if (r.submittedAt == 0) return false;
        if (r.resolved && !r.valid) return false;
        return r.signedStake >= r.stakeThreshold;
    }

    /**
     * @notice Look up the STARK commitment associated with a given proof hash.
     */
    function commitmentForProof(bytes32 proofHash)
        external
        view
        returns (bytes32)
    {
        return proofHashToCommitment[proofHash];
    }

    /**
     * @notice Check whether the challenge window for a commitment has expired.
     */
    function isChallengeWindowExpired(bytes32 starkCommitment)
        external
        view
        returns (bool)
    {
        CommitmentRecord storage r = records[starkCommitment];
        if (r.submittedAt == 0) return false;
        return block.timestamp >= r.submittedAt + challengeWindowSeconds;
    }
}
