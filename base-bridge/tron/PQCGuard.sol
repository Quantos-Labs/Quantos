// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================================
// PQC-Guard for Tron (TVM) — self-contained, flattened deployment unit.
//
// Tron's TVM is EVM-compatible, so the PQC-Guard contracts are byte-identical
// to the Ethereum reference (pqc-guard/src/*). This single file flattens the
// libraries + oracle + verifier + account so it can be deployed via TronBox or
// Remix/TronLink without a package manager.
//
// Anchoring: `QuantosAttestorOracle` reads `isProofVerified(bytes32)` from the
// already-deployed `QuantosL0VerifierTron` (base-bridge/tron/QuantosL0Verifier.sol)
// — same interface as the EVM L0 verifier. `block.chainid` returns Tron's chain
// id, which is bound into the authorization digest (spec §3).
//
// TRON BUILD NOTE: set `evmVersion = "paris"` (or compile with 0.8.19) so the
// PUSH0 opcode is not emitted; some TVM versions reject it.
//
// TESTNET ONLY. // AUDIT REQUIRED.
// ============================================================================

// ───────────────────────────── libraries ──────────────────────────────────

/// @title WOTS — Winternitz One-Time Signature verification (keccak256-based).
/// Identical construction to the EVM/Move/Rust ports (MULTIVM_SPEC.md §2).
library WOTS {
    uint256 internal constant W = 16;
    uint256 internal constant LEN1 = 64;
    uint256 internal constant LEN2 = 3;
    uint256 internal constant LEN = 67;

    error BadSignatureLength(uint256 got, uint256 expected);

    function pubKeyFromSig(bytes32 digest, bytes32[] memory sig)
        internal
        pure
        returns (bytes32 wotsPub)
    {
        if (sig.length != LEN) revert BadSignatureLength(sig.length, LEN);

        uint8[LEN] memory d = digits(digest);
        bytes32[] memory ends = new bytes32[](LEN);

        for (uint256 i = 0; i < LEN; i++) {
            bytes32 x = sig[i];
            for (uint256 j = uint256(d[i]); j < W - 1; j++) {
                x = keccak256(abi.encodePacked(x));
            }
            ends[i] = x;
        }
        wotsPub = keccak256(abi.encodePacked(ends));
    }

    function digits(bytes32 digest) internal pure returns (uint8[LEN] memory d) {
        uint256 csum = 0;
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(digest[i]);
            uint8 hi = b >> 4;
            uint8 lo = b & 0x0f;
            d[2 * i] = hi;
            d[2 * i + 1] = lo;
            csum += (W - 1 - uint256(hi));
            csum += (W - 1 - uint256(lo));
        }
        d[64] = uint8((csum >> 8) & 0x0f);
        d[65] = uint8((csum >> 4) & 0x0f);
        d[66] = uint8(csum & 0x0f);
    }
}

/// @title MerkleOTS — index-addressed keccak256 Merkle membership.
library MerkleOTS {
    function leaf(bytes32 wotsPub) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("PQCG_WOTS_LEAF", wotsPub));
    }

    function rootFromLeaf(bytes32 leafHash, uint256 index, bytes32[] memory path)
        internal
        pure
        returns (bytes32 root)
    {
        bytes32 h = leafHash;
        uint256 idx = index;
        for (uint256 i = 0; i < path.length; i++) {
            if (idx & 1 == 0) {
                h = keccak256(abi.encodePacked(h, path[i]));
            } else {
                h = keccak256(abi.encodePacked(path[i], h));
            }
            idx >>= 1;
        }
        root = h;
    }
}

/// @title AttestorSet — leaf encoding for the Quantos-finalized attestor set.
library AttestorSet {
    function leaf(bytes32 attestorId, bytes32 wotsRoot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("PQCG_ATTESTOR_LEAF", attestorId, wotsRoot));
    }
}

// ───────────────────────────── interfaces ─────────────────────────────────

/// @notice Minimal surface of the deployed `QuantosL0VerifierTron`.
interface IL0ProofRegistry {
    function isProofVerified(bytes32 proofHash) external view returns (bool);
}

interface IAttestorSetOracle {
    function attestorSetRoot() external view returns (bytes32);
    function attestorEpoch() external view returns (uint64);
    function threshold() external view returns (uint256);
}

interface IAttestationVerifier {
    function verifyAuthorization(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes calldata attestation
    ) external view returns (bool);

    function authorizationDigest(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) external view returns (bytes32);
}

// ───────────────────────────── oracle ─────────────────────────────────────

/// @title QuantosAttestorOracle (Tron) — the QTS anchor, fed by L0 proofs.
contract QuantosAttestorOracle is IAttestorSetOracle {
    IL0ProofRegistry public immutable l0Verifier;
    address public owner;

    bytes32 private _attestorSetRoot;
    uint64 private _attestorEpoch;
    uint256 private _threshold;

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

    function attestorSetRoot() external view returns (bytes32) { return _attestorSetRoot; }
    function attestorEpoch() external view returns (uint64) { return _attestorEpoch; }
    function threshold() external view returns (uint256) { return _threshold; }
}

// ───────────────────────────── verifier ───────────────────────────────────

/// @title StakeAttestationVerifier (Tron) — Phase-1 IAttestationVerifier.
contract StakeAttestationVerifier is IAttestationVerifier {
    IAttestorSetOracle public immutable oracle;

    struct AttestorProof {
        bytes32 attestorId;
        bytes32 wotsRoot;
        uint256 leafIndex;
        bytes32[] wotsSig;
        bytes32[] merklePath;
        uint256 setIndex;
        bytes32[] setProof;
    }

    constructor(IAttestorSetOracle _oracle) {
        oracle = _oracle;
    }

    function authorizationDigest(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encode(account, to, value, keccak256(data), nonce, block.chainid));
    }

    function verifyAuthorization(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes calldata attestation
    ) external view returns (bool) {
        bytes32 digest = authorizationDigest(account, to, value, data, nonce);

        AttestorProof[] memory proofs = abi.decode(attestation, (AttestorProof[]));
        uint256 thr = oracle.threshold();
        bytes32 setRoot = oracle.attestorSetRoot();

        uint256 valid = 0;
        bytes32[] memory seen = new bytes32[](proofs.length);
        uint256 seenLen = 0;

        for (uint256 i = 0; i < proofs.length; i++) {
            AttestorProof memory p = proofs[i];
            if (_contains(seen, seenLen, p.attestorId)) continue;

            bytes32 wotsPub = WOTS.pubKeyFromSig(digest, p.wotsSig);
            bytes32 treeRoot = MerkleOTS.rootFromLeaf(MerkleOTS.leaf(wotsPub), p.leafIndex, p.merklePath);
            if (treeRoot != p.wotsRoot) continue;

            bytes32 attestorLeaf = AttestorSet.leaf(p.attestorId, p.wotsRoot);
            bytes32 recomputedSetRoot = MerkleOTS.rootFromLeaf(attestorLeaf, p.setIndex, p.setProof);
            if (recomputedSetRoot != setRoot) continue;

            seen[seenLen] = p.attestorId;
            seenLen += 1;
            valid += 1;
            if (valid >= thr) return true;
        }
        return valid >= thr;
    }

    function _contains(bytes32[] memory arr, uint256 len, bytes32 x) private pure returns (bool) {
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == x) return true;
        }
        return false;
    }
}

// ───────────────────────────── account ────────────────────────────────────

/// @title PQCGuardAccount (Tron) — quantum-resistant smart account holding TRX.
contract PQCGuardAccount {
    uint256 public constant COMMIT_DELAY = 24 hours;
    uint256 public constant RECOVERY_TIMEOUT = 30 days;

    bytes32 public pqcCommitment;
    address public legacyOwner;
    bool public migrated;
    uint256 public migrationTime;
    uint256 public nonce;
    address public attestationVerifier;
    uint256 public lastActivity;

    bytes32 public pendingCommitment;
    uint256 public migrationCommitTime;
    address public pendingVerifier;

    address[] public guardians;
    mapping(address => bool) public isGuardian;
    uint256 public guardianThreshold;

    struct Recovery {
        bytes32 newCommitment;
        address newVerifier;
        address fundsRecipient;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approved;
    }

    mapping(bytes32 => Recovery) private _recoveries;

    event MigrationCommitted(bytes32 indexed commitment, address verifier, uint256 finalizeAfter);
    event MigrationCancelled(bytes32 indexed commitment);
    event Migrated(bytes32 indexed commitment, address verifier, uint256 time);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event Executed(address indexed to, uint256 value, uint256 nonce, bytes4 selector);
    event RecoveryProposed(bytes32 indexed id, bytes32 newCommitment, address newVerifier, address fundsRecipient);
    event RecoveryApproved(bytes32 indexed id, address indexed guardian, uint256 approvals);
    event RecoveryExecuted(bytes32 indexed id);
    event Deposited(address indexed from, uint256 amount);

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

    constructor(address _legacyOwner) {
        legacyOwner = _legacyOwner;
        lastActivity = block.timestamp;
    }

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
        _setGuardians(_guardians, _guardianThreshold);
        emit MigrationCommitted(commitment, verifier, block.timestamp + COMMIT_DELAY);
    }

    function cancelMigration() external onlyLegacyOwner {
        if (pendingCommitment == bytes32(0)) revert NoPendingMigration();
        bytes32 c = pendingCommitment;
        pendingCommitment = bytes32(0);
        pendingVerifier = address(0);
        migrationCommitTime = 0;
        emit MigrationCancelled(c);
    }

    function finalizeMigration(bytes calldata pqcPubKey) external onlyLegacyOwner {
        if (migrated) revert AlreadyMigrated();
        if (pendingCommitment == bytes32(0)) revert NoPendingMigration();
        uint256 readyAt = migrationCommitTime + COMMIT_DELAY;
        if (block.timestamp < readyAt) revert CommitNotReady(block.timestamp, readyAt);
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

    function execute(address to, uint256 value, bytes calldata data, bytes calldata attestation)
        external
        returns (bytes memory result)
    {
        if (!migrated) revert NotMigrated();
        bool ok = IAttestationVerifier(attestationVerifier).verifyAuthorization(
            pqcCommitment, to, value, data, nonce, attestation
        );
        if (!ok) revert Unauthorized();

        uint256 usedNonce = nonce;
        nonce = usedNonce + 1;
        lastActivity = block.timestamp;

        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        bool success;
        (success, result) = to.call{value: value}(data);
        if (!success) revert CallFailed(result);
        emit Executed(to, value, usedNonce, selector);
    }

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
        _approve(id, msg.sender);
    }

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

    function executeRecovery(bytes32 id) external {
        Recovery storage r = _recoveries[id];
        if (r.executed) revert RecoveryAlreadyExecuted();
        if (r.approvals < guardianThreshold) revert QuorumNotReached(r.approvals, guardianThreshold);
        uint256 idleUntil = lastActivity + RECOVERY_TIMEOUT;
        if (block.timestamp < idleUntil) revert NotIdleYet(block.timestamp, idleUntil);

        r.executed = true;
        if (r.fundsRecipient != address(0)) {
            uint256 bal = address(this).balance;
            (bool ok,) = r.fundsRecipient.call{value: bal}("");
            if (!ok) revert CallFailed("");
        } else {
            if (r.newCommitment != bytes32(0)) {
                pqcCommitment = r.newCommitment;
                migrated = true;
            }
            if (r.newVerifier != address(0)) {
                emit VerifierUpdated(attestationVerifier, r.newVerifier);
                attestationVerifier = r.newVerifier;
            }
        }
        lastActivity = block.timestamp;
        emit RecoveryExecuted(id);
    }

    function recoveryApprovals(bytes32 id) external view returns (uint256) {
        return _recoveries[id].approvals;
    }

    function _setGuardians(address[] calldata _guardians, uint256 _threshold) private {
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

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }
}
