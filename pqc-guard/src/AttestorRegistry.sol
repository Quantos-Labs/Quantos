// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WOTS, MerkleOTS} from "./lib/WOTS.sol";

/// @notice Minimal ERC20 surface used for staking. Avoids an external dependency
/// for this POC; deployments use the bundled `MockERC20`.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title AttestorRegistry
/// @notice Registry of staked attestors for PQC-Guard Phase 1.
///
/// Each attestor:
///   - deposits `stakeToken` (>= minStake),
///   - commits a Merkle root over many one-time Winternitz (WOTS) public keys
///     (XMSS-style tree). Leaves are consumed one index at a time.
///
/// The registry is the single source of truth for `StakeAttestationVerifier`:
/// it answers "is X an active, non-slashed attestor?" and "what is X's root?".
///
/// ## Slashing — the teeth behind the one-time rule
/// A WOTS key is one-time: signing two different messages with the SAME leaf
/// leaks the secret key. `slashOnReuse` accepts two valid attestations from the
/// same attestor at the same leaf index over DIFFERENT digests as fraud proof
/// and zeroes the attestor's stake (rewarding the reporter).
///
/// @dev POC / TESTNET ONLY. // AUDIT REQUIRED throughout.
contract AttestorRegistry {
    using WOTS for bytes32;

    struct Attestor {
        uint256 stake;
        bytes32 wotsRoot;
        bool active;
        bool slashed;
    }

    // ── Config ──
    IERC20 public immutable stakeToken;
    uint256 public immutable minStake;
    address public owner;
    /// @notice M in "M-of-N": minimum distinct attestors required for a quorum.
    uint256 public threshold;
    /// @notice Fraction (bps) of a slashed stake paid to the fraud reporter.
    uint256 public constant REPORTER_REWARD_BPS = 1000; // 10%

    // ── State ──
    mapping(address => Attestor) private _attestors;
    address[] public attestorList;
    uint256 public activeCount;
    /// @notice Treasury balance accrued from slashing (held in this contract).
    uint256 public slashTreasury;

    // ── Events ──
    event AttestorRegistered(address indexed attestor, bytes32 wotsRoot, uint256 stake);
    event StakeIncreased(address indexed attestor, uint256 amount, uint256 newStake);
    event AttestorDeactivated(address indexed attestor);
    event RootRotated(address indexed attestor, bytes32 oldRoot, bytes32 newRoot);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);
    event AttestorSlashed(address indexed attestor, address indexed reporter, uint256 slashed, uint256 reward);
    event StakeWithdrawn(address indexed attestor, uint256 amount);

    // ── Errors ──
    error NotOwner();
    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientStake(uint256 provided, uint256 required);
    error TransferFailed();
    error AttestorIsSlashed();
    error InvalidThreshold();
    error NotFraud();
    error StillActive();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IERC20 _stakeToken, uint256 _minStake, uint256 _threshold) {
        stakeToken = _stakeToken;
        minStake = _minStake;
        threshold = _threshold;
        owner = msg.sender;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestor lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Register as an attestor by staking and committing a WOTS Merkle root.
    /// @param wotsRoot Merkle root over the attestor's one-time WOTS public keys.
    /// @param amount   Stake amount (must be >= minStake). Pulled via transferFrom.
    function register(bytes32 wotsRoot, uint256 amount) external {
        Attestor storage a = _attestors[msg.sender];
        if (a.wotsRoot != bytes32(0) || a.active) revert AlreadyRegistered();
        if (a.slashed) revert AttestorIsSlashed();
        if (amount < minStake) revert InsufficientStake(amount, minStake);

        if (!stakeToken.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();

        a.stake = amount;
        a.wotsRoot = wotsRoot;
        a.active = true;
        attestorList.push(msg.sender);
        activeCount += 1;

        emit AttestorRegistered(msg.sender, wotsRoot, amount);
    }

    /// @notice Add more stake to an existing registration.
    function increaseStake(uint256 amount) external {
        Attestor storage a = _attestors[msg.sender];
        if (!a.active) revert NotRegistered();
        if (a.slashed) revert AttestorIsSlashed();
        if (!stakeToken.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        a.stake += amount;
        emit StakeIncreased(msg.sender, amount, a.stake);
    }

    /// @notice Rotate to a fresh WOTS tree (e.g. after exhausting leaf indices).
    /// @dev // AUDIT REQUIRED: rotating discards the registry's view of consumed
    /// leaves. In production, couple rotation with on-chain leaf-usage tracking
    /// or an epoch boundary so old-tree reuse cannot be laundered by rotating.
    function rotateRoot(bytes32 newRoot) external {
        Attestor storage a = _attestors[msg.sender];
        if (!a.active) revert NotRegistered();
        if (a.slashed) revert AttestorIsSlashed();
        bytes32 old = a.wotsRoot;
        a.wotsRoot = newRoot;
        emit RootRotated(msg.sender, old, newRoot);
    }

    /// @notice Voluntarily deactivate. Stake withdrawal is gated by {withdrawStake}.
    function deactivate() external {
        Attestor storage a = _attestors[msg.sender];
        if (!a.active) revert NotRegistered();
        a.active = false;
        if (activeCount > 0) activeCount -= 1;
        emit AttestorDeactivated(msg.sender);
    }

    /// @notice Withdraw stake after deactivation (no unbonding period in this POC).
    /// @dev // AUDIT REQUIRED: production must add an unbonding delay so an
    /// attestor cannot front-run a slashing report by exiting.
    function withdrawStake() external {
        Attestor storage a = _attestors[msg.sender];
        if (a.active) revert StillActive();
        if (a.slashed) revert AttestorIsSlashed();
        uint256 amt = a.stake;
        a.stake = 0;
        if (!stakeToken.transfer(msg.sender, amt)) revert TransferFailed();
        emit StakeWithdrawn(msg.sender, amt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Governance
    // ─────────────────────────────────────────────────────────────────────────

    function setThreshold(uint256 newThreshold) external onlyOwner {
        if (newThreshold == 0) revert InvalidThreshold();
        uint256 old = threshold;
        threshold = newThreshold;
        emit ThresholdUpdated(old, newThreshold);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slashing — fraud proof for WOTS one-time reuse
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Slash an attestor that signed two different digests with the SAME
    /// one-time leaf. Anyone can submit the proof and earn a reporter reward.
    /// @param attestor  The accused attestor.
    /// @param leafIndex The reused leaf index.
    /// @param digestA   First authorization digest.
    /// @param sigA      WOTS signature for digestA (67 elements).
    /// @param pathA     Merkle path proving the WOTS key is leaf[leafIndex].
    /// @param digestB   Second authorization digest (must differ from digestA).
    /// @param sigB      WOTS signature for digestB (67 elements).
    /// @param pathB     Merkle path for the same leaf index.
    /// @dev Both signatures must verify against the attestor's committed root at
    /// the SAME index over DIFFERENT digests — that is provable key reuse.
    /// // AUDIT REQUIRED
    function slashOnReuse(
        address attestor,
        uint256 leafIndex,
        bytes32 digestA,
        bytes32[] calldata sigA,
        bytes32[] calldata pathA,
        bytes32 digestB,
        bytes32[] calldata sigB,
        bytes32[] calldata pathB
    ) external {
        Attestor storage a = _attestors[attestor];
        if (a.wotsRoot == bytes32(0)) revert NotRegistered();
        if (a.slashed) revert AttestorIsSlashed();
        if (digestA == digestB) revert NotFraud();

        bytes32 root = a.wotsRoot;

        // Both must be valid one-time signatures at the SAME leaf index.
        bytes32 rootA = MerkleOTS.rootFromLeaf(
            MerkleOTS.leaf(WOTS.pubKeyFromSig(digestA, _toMemory(sigA))), leafIndex, _toMemory(pathA)
        );
        bytes32 rootB = MerkleOTS.rootFromLeaf(
            MerkleOTS.leaf(WOTS.pubKeyFromSig(digestB, _toMemory(sigB))), leafIndex, _toMemory(pathB)
        );
        if (rootA != root || rootB != root) revert NotFraud();

        // Proven reuse → slash.
        uint256 amount = a.stake;
        a.stake = 0;
        a.slashed = true;
        if (a.active) {
            a.active = false;
            if (activeCount > 0) activeCount -= 1;
        }

        uint256 reward = (amount * REPORTER_REWARD_BPS) / 10_000;
        uint256 remainder = amount - reward;
        slashTreasury += remainder;

        if (reward > 0) {
            if (!stakeToken.transfer(msg.sender, reward)) revert TransferFailed();
        }

        emit AttestorSlashed(attestor, msg.sender, amount, reward);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Views (consumed by StakeAttestationVerifier)
    // ─────────────────────────────────────────────────────────────────────────

    function isActive(address attestor) external view returns (bool) {
        Attestor storage a = _attestors[attestor];
        return a.active && !a.slashed;
    }

    function rootOf(address attestor) external view returns (bytes32) {
        return _attestors[attestor].wotsRoot;
    }

    function isSlashed(address attestor) external view returns (bool) {
        return _attestors[attestor].slashed;
    }

    function stakeOf(address attestor) external view returns (uint256) {
        return _attestors[attestor].stake;
    }

    function attestorCount() external view returns (uint256) {
        return attestorList.length;
    }

    function getAttestor(address attestor)
        external
        view
        returns (uint256 stake, bytes32 wotsRoot, bool active, bool slashed)
    {
        Attestor storage a = _attestors[attestor];
        return (a.stake, a.wotsRoot, a.active, a.slashed);
    }

    // ── internal ──

    /// @dev Copy a calldata bytes32[] into memory (libraries take memory arrays).
    function _toMemory(bytes32[] calldata arr) private pure returns (bytes32[] memory out) {
        out = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
