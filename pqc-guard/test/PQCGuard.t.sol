// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {AttestorRegistry, IERC20} from "../src/AttestorRegistry.sol";
import {StakeAttestationVerifier} from "../src/StakeAttestationVerifier.sol";
import {QuantosAttestorOracle, IL0ProofRegistry} from "../src/QuantosAttestorOracle.sol";
import {PQCGuardAccount} from "../src/PQCGuardAccount.sol";
import {WOTS, MerkleOTS} from "../src/lib/WOTS.sol";
import {AttestorSet} from "../src/lib/AttestorSet.sol";
import {WOTSSigner} from "./helpers/WOTSSigner.sol";
import {MockL0ProofRegistry} from "./helpers/MockL0ProofRegistry.sol";

/// @notice Full test suite for the PQC-Guard MVP. Covers every case required by
/// the spec: migration (ok/non-owner), commit delay, quorum reached/not,
/// attestation replay, legacy-ECDSA-after-migration, slashing, escape hatch.
contract PQCGuardTest is Test {
    MockERC20 internal stake;
    AttestorRegistry internal registry; // local mirror for slashing reference tests
    QuantosAttestorOracle internal oracle; // the QTS anchor (fed by L0 proofs)
    MockL0ProofRegistry internal mockL0;
    StakeAttestationVerifier internal verifier;
    PQCGuardAccount internal account;
    WOTSSigner internal signer;

    // Attestor identities
    uint256 internal constant N = 3;
    uint256 internal constant THRESHOLD = 2;
    uint256 internal constant TREE_HEIGHT = 3; // 8 one-time leaves each
    uint256 internal constant MIN_STAKE = 1 ether;

    address[N] internal attestors;
    bytes32[N] internal seeds;
    bytes32[N] internal attestorIds; // Quantos validator ids (distinctness key)
    bytes32[N] internal wotsRoots;   // each attestor's committed WOTS tree root
    bytes32[] internal setLeaves;    // finalized attestor-set leaves (from Quantos)

    // Account actors
    address internal legacyOwner = address(0xA11CE);
    address[] internal guardians;
    uint256 internal constant GUARDIAN_THRESHOLD = 2;

    // PQC key material (opaque bytes; real key comes from SLH-DSA off-chain)
    bytes internal pqcPubKey = hex"deadbeefcafef00dba5eba11";
    bytes32 internal commitment;

    address internal recipient = address(0xBEEF);

    function setUp() public {
        stake = new MockERC20();
        registry = new AttestorRegistry(IERC20(address(stake)), MIN_STAKE, THRESHOLD);
        signer = new WOTSSigner();
        mockL0 = new MockL0ProofRegistry();
        oracle = new QuantosAttestorOracle(IL0ProofRegistry(address(mockL0)), address(this));
        verifier = new StakeAttestationVerifier(oracle);

        // Build N attestors. Each is a Quantos validator (mirrored in the local
        // AttestorRegistry so the slashing reference tests still run), with its
        // own WOTS Merkle tree. We also assemble the finalized attestor-set
        // leaves which, on Quantos, are committed and exported via an L0 proof.
        for (uint256 i = 0; i < N; i++) {
            attestors[i] = address(uint160(0x1000 + i));
            seeds[i] = keccak256(abi.encodePacked("attestor-seed", i));
            bytes32 root = signer.buildRoot(seeds[i], TREE_HEIGHT);
            attestorIds[i] = bytes32(uint256(i + 1));
            wotsRoots[i] = root;
            setLeaves.push(AttestorSet.leaf(attestorIds[i], root));

            // Local registry mirror (slashing reference; in prod this is Rust/Quantos).
            stake.mint(attestors[i], MIN_STAKE);
            vm.startPrank(attestors[i]);
            stake.approve(address(registry), MIN_STAKE);
            registry.register(root, MIN_STAKE);
            vm.stopPrank();
        }

        // Publish the finalized attestor-set root to the oracle, as if delivered
        // by a verified L0 finality proof from Quantos.
        _publishSet(setLeaves, 1);

        // Guardians for the escape hatch.
        guardians.push(address(0x6001));
        guardians.push(address(0x6002));
        guardians.push(address(0x6003));

        // Deploy account and fund it.
        account = new PQCGuardAccount(legacyOwner);
        vm.deal(address(account), 10 ether);

        commitment = keccak256(pqcPubKey);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sanity: WOTS + Merkle round-trip (catches signer/verifier encoding drift)
    // ─────────────────────────────────────────────────────────────────────────

    function test_WOTS_RoundTrip() public view {
        bytes32 digest = keccak256("hello pqc");
        uint256 leaf = 2;
        bytes32[] memory sig = signer.sign(seeds[0], leaf, digest);

        bytes32 recomputedPub = WOTS.pubKeyFromSig(digest, sig);
        assertEq(recomputedPub, signer.wotsPubKey(seeds[0], leaf), "WOTS pubkey mismatch");

        bytes32[] memory path = signer.authPath(seeds[0], TREE_HEIGHT, leaf);
        bytes32 root = MerkleOTS.rootFromLeaf(MerkleOTS.leaf(recomputedPub), leaf, path);
        assertEq(root, wotsRoots[0], "Merkle root mismatch");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Migration
    // ─────────────────────────────────────────────────────────────────────────

    function _commitMigration() internal {
        vm.prank(legacyOwner);
        account.migrate(commitment, address(verifier), guardians, GUARDIAN_THRESHOLD);
    }

    function _finalizeMigration() internal {
        _commitMigration();
        vm.warp(block.timestamp + account.COMMIT_DELAY());
        vm.prank(legacyOwner);
        account.finalizeMigration(pqcPubKey);
    }

    function test_Migration_Success() public {
        _finalizeMigration();
        assertTrue(account.migrated(), "should be migrated");
        assertEq(account.pqcCommitment(), commitment, "commitment set");
        assertEq(account.attestationVerifier(), address(verifier), "verifier set");
    }

    function test_Migration_RevertNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(PQCGuardAccount.NotLegacyOwner.selector);
        account.migrate(commitment, address(verifier), guardians, GUARDIAN_THRESHOLD);
    }

    function test_Migration_RevertBeforeDelay() public {
        _commitMigration();
        // Try to finalize immediately — delay not elapsed.
        vm.prank(legacyOwner);
        vm.expectRevert();
        account.finalizeMigration(pqcPubKey);
    }

    function test_Migration_RevertBadReveal() public {
        _commitMigration();
        vm.warp(block.timestamp + account.COMMIT_DELAY());
        vm.prank(legacyOwner);
        vm.expectRevert(PQCGuardAccount.BadCommitmentReveal.selector);
        account.finalizeMigration(hex"00112233"); // wrong preimage
    }

    function test_CancelMigration() public {
        _commitMigration();
        vm.prank(legacyOwner);
        account.cancelMigration();
        assertEq(account.pendingCommitment(), bytes32(0), "pending cleared");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation building helper
    // ─────────────────────────────────────────────────────────────────────────

    function _buildAttestation(
        bytes32 acct,
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce_,
        uint256[] memory attestorIdx,
        uint256[] memory leafIdx
    ) internal view returns (bytes memory) {
        bytes32 digest = verifier.authorizationDigest(acct, to, value, data, nonce_);

        StakeAttestationVerifier.AttestorProof[] memory proofs =
            new StakeAttestationVerifier.AttestorProof[](attestorIdx.length);

        for (uint256 i = 0; i < attestorIdx.length; i++) {
            uint256 a = attestorIdx[i];
            bytes32[] memory sig = signer.sign(seeds[a], leafIdx[i], digest);
            bytes32[] memory path = signer.authPath(seeds[a], TREE_HEIGHT, leafIdx[i]);

            // Membership of {attestorId, wotsRoot} in the finalized set root.
            bytes32 leaf = AttestorSet.leaf(attestorIds[a], wotsRoots[a]);
            uint256 setIdx = _indexOf(leaf);
            bytes32[] memory setProof = signer.merklePath(setLeaves, setIdx);

            proofs[i] = StakeAttestationVerifier.AttestorProof({
                attestorId: attestorIds[a],
                wotsRoot: wotsRoots[a],
                leafIndex: leafIdx[i],
                wotsSig: sig,
                merklePath: path,
                setIndex: setIdx,
                setProof: setProof
            });
        }
        return abi.encode(proofs);
    }

    /// @dev Find a leaf's index in the current finalized set (0 if absent, which
    /// makes the membership proof fail — used intentionally by negative tests).
    function _indexOf(bytes32 leaf) internal view returns (uint256) {
        for (uint256 i = 0; i < setLeaves.length; i++) {
            if (setLeaves[i] == leaf) return i;
        }
        return 0;
    }

    /// @dev Simulate Quantos publishing a finalized attestor set via L0 proof.
    function _publishSet(bytes32[] memory leaves, uint64 epoch) internal {
        bytes32 root = signer.merkleRoot(leaves);
        bytes32 proofHash = keccak256(abi.encodePacked("l0-proof", epoch));
        mockL0.setVerified(proofHash, true);
        oracle.updateAttestorSet(root, epoch, THRESHOLD, proofHash);
    }

    function _u(uint256 a, uint256 b) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function _u1(uint256 a) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](1);
        arr[0] = a;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execute
    // ─────────────────────────────────────────────────────────────────────────

    function test_Execute_QuorumReached_Success() public {
        _finalizeMigration();

        uint256 value = 1 ether;
        bytes memory data = "";
        bytes memory attestation =
            _buildAttestation(commitment, recipient, value, data, 0, _u(0, 1), _u(0, 0));

        uint256 balBefore = recipient.balance;
        // Anyone may relay; use a random relayer.
        vm.prank(address(0x7777));
        account.execute(recipient, value, data, attestation);

        assertEq(recipient.balance, balBefore + value, "funds moved");
        assertEq(account.nonce(), 1, "nonce incremented");
    }

    function test_Execute_QuorumNotReached_Revert() public {
        _finalizeMigration();

        bytes memory data = "";
        // Only ONE attestor → below THRESHOLD=2.
        bytes memory attestation =
            _buildAttestation(commitment, recipient, 1 ether, data, 0, _u1(0), _u1(0));

        vm.expectRevert(PQCGuardAccount.Unauthorized.selector);
        account.execute(recipient, 1 ether, data, attestation);
    }

    function test_Execute_ReplayRevert() public {
        _finalizeMigration();

        bytes memory data = "";
        bytes memory attestation =
            _buildAttestation(commitment, recipient, 1 ether, data, 0, _u(0, 1), _u(0, 0));

        // First execution at nonce 0 succeeds.
        account.execute(recipient, 1 ether, data, attestation);

        // Replaying the SAME attestation now fails: account nonce is 1, so the
        // digest no longer matches what the attestors signed.
        vm.expectRevert(PQCGuardAccount.Unauthorized.selector);
        account.execute(recipient, 1 ether, data, attestation);
    }

    function test_LegacyECDSA_CannotSpend_AfterMigration() public {
        _finalizeMigration();

        // The legacy owner has NO spending path: execute requires a valid PQC
        // attestation regardless of msg.sender. An empty attestation reverts.
        StakeAttestationVerifier.AttestorProof[] memory empty =
            new StakeAttestationVerifier.AttestorProof[](0);
        bytes memory emptyAttestation = abi.encode(empty);

        vm.prank(legacyOwner);
        vm.expectRevert(PQCGuardAccount.Unauthorized.selector);
        account.execute(recipient, 1 ether, "", emptyAttestation);
    }

    function test_Execute_RevertIfNotMigrated() public {
        bytes memory data = "";
        bytes memory attestation =
            _buildAttestation(commitment, recipient, 1 ether, data, 0, _u(0, 1), _u(0, 0));
        vm.expectRevert(PQCGuardAccount.NotMigrated.selector);
        account.execute(recipient, 1 ether, data, attestation);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slashing — WOTS one-time reuse
    // ─────────────────────────────────────────────────────────────────────────

    function test_Slashing_DoubleSign() public {
        // Attestor 0 signs TWO different digests with the SAME leaf index 5.
        uint256 leaf = 5;
        bytes32 digestA = keccak256("message A");
        bytes32 digestB = keccak256("message B");

        bytes32[] memory sigA = signer.sign(seeds[0], leaf, digestA);
        bytes32[] memory pathA = signer.authPath(seeds[0], TREE_HEIGHT, leaf);
        bytes32[] memory sigB = signer.sign(seeds[0], leaf, digestB);
        bytes32[] memory pathB = signer.authPath(seeds[0], TREE_HEIGHT, leaf);

        address reporter = address(0x9999);
        uint256 stakeBefore = registry.stakeOf(attestors[0]);
        assertEq(stakeBefore, MIN_STAKE);

        vm.prank(reporter);
        registry.slashOnReuse(attestors[0], leaf, digestA, sigA, pathA, digestB, sigB, pathB);

        assertTrue(registry.isSlashed(attestors[0]), "slashed");
        assertFalse(registry.isActive(attestors[0]), "deactivated");
        assertEq(registry.stakeOf(attestors[0]), 0, "stake zeroed");

        // Reporter earns 10% reward.
        assertEq(stake.balanceOf(reporter), (MIN_STAKE * 1000) / 10_000, "reporter reward");
    }

    function test_Slashing_RevertSameDigest() public {
        uint256 leaf = 5;
        bytes32 digest = keccak256("same");
        bytes32[] memory sig = signer.sign(seeds[0], leaf, digest);
        bytes32[] memory path = signer.authPath(seeds[0], TREE_HEIGHT, leaf);

        vm.expectRevert(AttestorRegistry.NotFraud.selector);
        registry.slashOnReuse(attestors[0], leaf, digest, sig, path, digest, sig, path);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QTS anchor — only Quantos-finalized attestors count
    // ─────────────────────────────────────────────────────────────────────────

    function test_AttestorNotInFinalizedSet_Rejected() public {
        _finalizeMigration();

        // attestor 1 is a real member; the second "attestor" carries a valid WOTS
        // signature but a fabricated id that is NOT in the Quantos-finalized set.
        bytes32 digest = verifier.authorizationDigest(commitment, recipient, 1 ether, "", 0);
        StakeAttestationVerifier.AttestorProof[] memory proofs =
            new StakeAttestationVerifier.AttestorProof[](2);

        {
            bytes32[] memory sig = signer.sign(seeds[1], 0, digest);
            bytes32[] memory path = signer.authPath(seeds[1], TREE_HEIGHT, 0);
            uint256 idx = _indexOf(AttestorSet.leaf(attestorIds[1], wotsRoots[1]));
            proofs[0] = StakeAttestationVerifier.AttestorProof({
                attestorId: attestorIds[1], wotsRoot: wotsRoots[1], leafIndex: 0,
                wotsSig: sig, merklePath: path, setIndex: idx,
                setProof: signer.merklePath(setLeaves, idx)
            });
        }
        {
            bytes32[] memory sig = signer.sign(seeds[0], 0, digest);
            bytes32[] memory path = signer.authPath(seeds[0], TREE_HEIGHT, 0);
            // Fabricated id not committed by Quantos → membership proof fails.
            proofs[1] = StakeAttestationVerifier.AttestorProof({
                attestorId: bytes32(uint256(0xDEAD)), wotsRoot: wotsRoots[0], leafIndex: 0,
                wotsSig: sig, merklePath: path, setIndex: 0,
                setProof: signer.merklePath(setLeaves, 0)
            });
        }

        // Only attestor 1 is a finalized member → 1 < threshold → revert.
        vm.expectRevert(PQCGuardAccount.Unauthorized.selector);
        account.execute(recipient, 1 ether, "", abi.encode(proofs));
    }

    function test_SlashedAttestorRemovedFromSet_NoQuorum() public {
        _finalizeMigration();

        // Quantos slashes attestor 0 (in QTS): the next finalized set EXCLUDES it.
        bytes32[] memory newLeaves = new bytes32[](2);
        newLeaves[0] = setLeaves[1];
        newLeaves[1] = setLeaves[2];
        setLeaves = newLeaves;
        _publishSet(setLeaves, 2);

        // Trying to use {removed 0, valid 1}: attestor 0 fails membership against
        // the new finalized root → only 1 valid → below threshold.
        bytes memory attestation =
            _buildAttestation(commitment, recipient, 1 ether, "", 0, _u(0, 1), _u(0, 0));
        vm.expectRevert(PQCGuardAccount.Unauthorized.selector);
        account.execute(recipient, 1 ether, "", attestation);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Escape hatch — funds never freeze
    // ─────────────────────────────────────────────────────────────────────────

    function test_EscapeHatch_BeforeTimeout_Revert() public {
        _finalizeMigration();
        vm.prank(guardians[0]);
        vm.expectRevert();
        account.proposeRecovery(bytes32(0), address(0), recipient);
    }

    function test_EscapeHatch_AfterTimeout_SweepFunds() public {
        _finalizeMigration();

        // Idle past the recovery timeout.
        vm.warp(block.timestamp + account.RECOVERY_TIMEOUT() + 1);

        address exitTo = address(0x5151);
        uint256 acctBal = address(account).balance;

        // Guardian 0 proposes an exit (sweep funds), implicitly approving.
        vm.prank(guardians[0]);
        bytes32 id = account.proposeRecovery(bytes32(0), address(0), exitTo);

        // Guardian 1 approves → quorum (2-of-3) reached.
        vm.prank(guardians[1]);
        account.approveRecovery(id);

        // Anyone executes.
        account.executeRecovery(id);

        assertEq(exitTo.balance, acctBal, "funds swept to recipient");
        assertEq(address(account).balance, 0, "account drained safely");
    }

    function test_EscapeHatch_RotateKey() public {
        _finalizeMigration();
        vm.warp(block.timestamp + account.RECOVERY_TIMEOUT() + 1);

        bytes32 newCommitment = keccak256("new-pqc-key");
        vm.prank(guardians[0]);
        bytes32 id = account.proposeRecovery(newCommitment, address(verifier), address(0));
        vm.prank(guardians[1]);
        account.approveRecovery(id);
        account.executeRecovery(id);

        assertEq(account.pqcCommitment(), newCommitment, "key rotated");
    }

    function test_EscapeHatch_NonGuardian_Revert() public {
        _finalizeMigration();
        vm.warp(block.timestamp + account.RECOVERY_TIMEOUT() + 1);
        vm.prank(address(0xDEAD));
        vm.expectRevert(PQCGuardAccount.NotGuardian.selector);
        account.proposeRecovery(bytes32(0), address(0), recipient);
    }
}
