// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {IAttestationVerifier} from "./interfaces/IAttestationVerifier.sol";

/// @title PQCGuardAccount — a quantum-resistant smart account
/// @notice Holds assets and replaces ECDSA authorization with post-quantum
/// authorization. Once migrated, spending is gated SOLELY by
/// `IAttestationVerifier.verifyAuthorization`; the legacy ECDSA owner can no
/// longer move funds.
///
/// ## Why this design
/// Verifying SPHINCS+/SLH-DSA on-chain is infeasible (>block gas limit). So the
/// account NEVER verifies it. It delegates authorization to a swappable
/// `IAttestationVerifier`:
///   - Phase 1: `StakeAttestationVerifier` (M-of-N hash-based attestors)
///   - Phase 2: `ZkStarkVerifier` (STARK proof of SPHINCS+) — drop-in, no change
///     to THIS contract.
///
/// ## Safety properties
///   - **Commit-delay-reveal migration**: a compromised ECDSA key cannot
///     instantly hijack the account; the real owner has `COMMIT_DELAY` (24h) to
///     cancel.
///   - **Anti-replay**: a monotonic `nonce` is bound into the attested digest.
///   - **Funds never freeze**: if the account is idle for `recoveryTimeout`
///     (30d), an M-of-N guardian quorum can rotate the key/verifier or exit
///     funds.
///
/// @dev POC / TESTNET ONLY. Do not deposit real value. // AUDIT REQUIRED.
contract PQCGuardAccount {
    // ── Constants (testnet timings) ──
    /// @notice Delay between committing and finalizing a migration.
    uint256 public constant COMMIT_DELAY = 24 hours;
    /// @notice Idle window after which guardians may recover the account.
    uint256 public constant RECOVERY_TIMEOUT = 30 days;

    // ── Core state ──
    /// @notice keccak256 of the SLH-DSA public key authorizing this account.
    bytes32 public pqcCommitment;
    /// @notice The original ECDSA owner. Loses spend power after migration.
    address public legacyOwner;
    /// @notice True once migration is finalized; ECDSA spending is then disabled.
    bool public migrated;
    /// @notice Timestamp at which migration was finalized.
    uint256 public migrationTime;
    /// @notice Monotonic anti-replay counter, bound into each attested digest.
    uint256 public nonce;
    /// @notice The swappable authorization verifier (Phase 1 → Phase 2 seam).
    address public attestationVerifier;
    /// @notice Last time the account executed or was touched (for escape hatch).
    uint256 public lastActivity;

    // ── Migration (commit-reveal) state ──
    bytes32 public pendingCommitment;
    uint256 public migrationCommitTime;
    address public pendingVerifier;

    // ── Guardian / recovery state ──
    address[] public guardians;
    mapping(address => bool) public isGuardian;
    uint256 public guardianThreshold;

    struct Recovery {
        bytes32 newCommitment;
        address newVerifier;
        address fundsRecipient; // if non-zero, sweep ETH here instead of rotating
        uint256 approvals;
        bool executed;
        mapping(address => bool) approved;
    }

    mapping(bytes32 => Recovery) private _recoveries;

    // ── Events ──
    event MigrationCommitted(bytes32 indexed commitment, address verifier, uint256 finalizeAfter);
    event MigrationCancelled(bytes32 indexed commitment);
    event Migrated(bytes32 indexed commitment, address verifier, uint256 time);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event Executed(address indexed to, uint256 value, uint256 nonce, bytes4 selector);
    event RecoveryProposed(bytes32 indexed id, bytes32 newCommitment, address newVerifier, address fundsRecipient);
    event RecoveryApproved(bytes32 indexed id, address indexed guardian, uint256 approvals);
    event RecoveryExecuted(bytes32 indexed id);
    event Deposited(address indexed from, uint256 amount);

    // ── Errors ──
    error NotLegacyOwner();
    error AlreadyMigrated();
    error NotMigrated();
    error CommitNotReady(uint256 nowTs, uint256 readyTs);
    error NoPendingMigration();
    error BadCommitmentReveal();
    error Unauthorized();
    error CallFailed(bytes returnData);
    error NotIdleYet(uint256 nowTs, uint256 idleUntil);
    error NotGuardian();
    error AlreadyApproved();
    error RecoveryAlreadyExecuted();
    error QuorumNotReached(uint256 approvals, uint256 required);
    error InvalidGuardianSet();

    modifier onlyLegacyOwner() {
        if (msg.sender != legacyOwner) revert NotLegacyOwner();
        _;
    }

    /// @param _legacyOwner The initial ECDSA owner (pre-migration controller).
    constructor(address _legacyOwner) {
        legacyOwner = _legacyOwner;
        lastActivity = block.timestamp;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Migration: commit → (24h delay) → reveal/finalize
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Step 1 of migration. Only the legacy ECDSA owner can start it.
    /// Begins the commit-delay window; nothing is enforced yet.
    /// @param commitment keccak256 of the SLH-DSA public key (the future authority).
    /// @param verifier   The IAttestationVerifier to use after migration.
    /// @param _guardians Guardian set for the escape hatch.
    /// @param _guardianThreshold M-of-N guardians required to recover.
    /// @dev // AUDIT REQUIRED: a compromised ECDSA key could call this; the
    /// 24h delay + {cancelMigration} is the mitigation. Consider also a
    /// pre-registered guardian veto in production.
    function migrate(
        bytes32 commitment,
        address verifier,
        address[] calldata _guardians,
        uint256 _guardianThreshold
    ) external onlyLegacyOwner {
        if (migrated) revert AlreadyMigrated();
        if (_guardians.length == 0 || _guardianThreshold == 0 || _guardianThreshold > _guardians.length) {
            revert InvalidGuardianSet();
        }

        pendingCommitment = commitment;
        pendingVerifier = verifier;
        migrationCommitTime = block.timestamp;

        // Reset and set guardians now (so a later key compromise can't change them
        // without the 24h window being observable on-chain).
        _setGuardians(_guardians, _guardianThreshold);

        emit MigrationCommitted(commitment, verifier, block.timestamp + COMMIT_DELAY);
    }

    /// @notice Abort a pending migration. Defends against a hijacked migrate().
    function cancelMigration() external onlyLegacyOwner {
        if (pendingCommitment == bytes32(0)) revert NoPendingMigration();
        bytes32 c = pendingCommitment;
        pendingCommitment = bytes32(0);
        pendingVerifier = address(0);
        migrationCommitTime = 0;
        emit MigrationCancelled(c);
    }

    /// @notice Step 2 of migration. After the 24h delay, reveal the SLH-DSA public
    /// key. We verify keccak256(pqcPubKey) == pendingCommitment, then lock in the
    /// post-quantum authority. ECDSA spending is disabled from here on.
    /// @param pqcPubKey The full SLH-DSA public key whose hash equals the commitment.
    function finalizeMigration(bytes calldata pqcPubKey) external onlyLegacyOwner {
        if (migrated) revert AlreadyMigrated();
        if (pendingCommitment == bytes32(0)) revert NoPendingMigration();

        uint256 readyAt = migrationCommitTime + COMMIT_DELAY;
        if (block.timestamp < readyAt) revert CommitNotReady(block.timestamp, readyAt);

        // Bind the revealed public key to the prior commitment. // AUDIT REQUIRED
        if (keccak256(pqcPubKey) != pendingCommitment) revert BadCommitmentReveal();

        pqcCommitment = pendingCommitment;
        attestationVerifier = pendingVerifier;
        migrated = true;
        migrationTime = block.timestamp;
        lastActivity = block.timestamp;

        pendingCommitment = bytes32(0);
        pendingVerifier = address(0);

        emit Migrated(pqcCommitment, attestationVerifier, migrationTime);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execution: post-quantum authorized calls ONLY
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Execute a call authorized by a post-quantum attestation.
    /// Anyone may relay (the attestation IS the authorization), but the call is
    /// only performed if the verifier accepts the attestation for the CURRENT
    /// nonce. After migration there is NO ECDSA path that can spend.
    /// @param to          Target address.
    /// @param value       ETH value to send.
    /// @param data        Calldata.
    /// @param attestation Verifier-specific proof bytes (Phase 1: AttestorProof[]).
    /// @return result     Raw return data from the call.
    function execute(address to, uint256 value, bytes calldata data, bytes calldata attestation)
        external
        returns (bytes memory result)
    {
        if (!migrated) revert NotMigrated();

        // The account identity passed to the verifier IS the pqcCommitment, so
        // the attestation is cryptographically bound to this specific PQC key.
        bool ok = IAttestationVerifier(attestationVerifier).verifyAuthorization(
            pqcCommitment, to, value, data, nonce, attestation
        );
        if (!ok) revert Unauthorized();

        // Effects before interaction (CEI): bump nonce first to kill re-entrant replay.
        uint256 usedNonce = nonce;
        nonce = usedNonce + 1;
        lastActivity = block.timestamp;

        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);

        bool success;
        (success, result) = to.call{value: value}(data);
        if (!success) revert CallFailed(result);

        emit Executed(to, value, usedNonce, selector);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Escape hatch: guardians can recover an idle account (funds never freeze)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Propose a recovery action. Guardians-only. Two modes:
    ///   - Rotate: set a new commitment and/or verifier (newCommitment != 0).
    ///   - Exit:   sweep all ETH to `fundsRecipient` (fundsRecipient != 0).
    /// @dev Only callable once the account has been idle for RECOVERY_TIMEOUT.
    /// // AUDIT REQUIRED: guardians authenticate via ECDSA here; in production a
    /// PQC guardian scheme (or hash-based) should replace this.
    function proposeRecovery(bytes32 newCommitment, address newVerifier, address fundsRecipient)
        external
        returns (bytes32 id)
    {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        uint256 idleUntil = lastActivity + RECOVERY_TIMEOUT;
        if (block.timestamp < idleUntil) revert NotIdleYet(block.timestamp, idleUntil);

        id = keccak256(abi.encode(newCommitment, newVerifier, fundsRecipient, lastActivity));
        Recovery storage r = _recoveries[id];
        r.newCommitment = newCommitment;
        r.newVerifier = newVerifier;
        r.fundsRecipient = fundsRecipient;

        emit RecoveryProposed(id, newCommitment, newVerifier, fundsRecipient);

        // Proposer implicitly approves.
        _approve(id, msg.sender);
    }

    /// @notice Approve a pending recovery. Guardians-only.
    function approveRecovery(bytes32 id) external {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        _approve(id, msg.sender);
    }

    function _approve(bytes32 id, address guardian) private {
        Recovery storage r = _recoveries[id];
        if (r.executed) revert RecoveryAlreadyExecuted();
        if (r.approved[guardian]) revert AlreadyApproved();

        r.approved[guardian] = true;
        r.approvals += 1;
        emit RecoveryApproved(id, guardian, r.approvals);
    }

    /// @notice Execute a recovery once the guardian quorum approves.
    /// Anyone can trigger the final step once approvals >= threshold.
    function executeRecovery(bytes32 id) external {
        Recovery storage r = _recoveries[id];
        if (r.executed) revert RecoveryAlreadyExecuted();
        if (r.approvals < guardianThreshold) revert QuorumNotReached(r.approvals, guardianThreshold);

        // Re-check idle window at execution time too.
        uint256 idleUntil = lastActivity + RECOVERY_TIMEOUT;
        if (block.timestamp < idleUntil) revert NotIdleYet(block.timestamp, idleUntil);

        r.executed = true;

        if (r.fundsRecipient != address(0)) {
            // Exit mode: sweep ETH out. Funds never freeze.
            uint256 bal = address(this).balance;
            (bool ok,) = r.fundsRecipient.call{value: bal}("");
            if (!ok) revert CallFailed("");
        } else {
            // Rotate mode: install a new PQC authority / verifier.
            if (r.newCommitment != bytes32(0)) {
                pqcCommitment = r.newCommitment;
                migrated = true; // ensure account stays in PQC mode
            }
            if (r.newVerifier != address(0)) {
                emit VerifierUpdated(attestationVerifier, r.newVerifier);
                attestationVerifier = r.newVerifier;
            }
        }

        lastActivity = block.timestamp; // reset idle clock post-recovery
        emit RecoveryExecuted(id);
    }

    function recoveryApprovals(bytes32 id) external view returns (uint256) {
        return _recoveries[id].approvals;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internals & funds
    // ─────────────────────────────────────────────────────────────────────────

    function _setGuardians(address[] calldata _guardians, uint256 _threshold) private {
        // Clear old set.
        for (uint256 i = 0; i < guardians.length; i++) {
            isGuardian[guardians[i]] = false;
        }
        delete guardians;

        for (uint256 i = 0; i < _guardians.length; i++) {
            address g = _guardians[i];
            if (g == address(0) || isGuardian[g]) revert InvalidGuardianSet();
            isGuardian[g] = true;
            guardians.push(g);
        }
        guardianThreshold = _threshold;
    }

    function guardianCount() external view returns (uint256) {
        return guardians.length;
    }

    /// @notice Accept ETH deposits.
    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }
}
