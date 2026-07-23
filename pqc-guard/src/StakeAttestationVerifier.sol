// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {IAttestationVerifier} from "./interfaces/IAttestationVerifier.sol";
import {IAttestorSetOracle} from "./interfaces/IAttestorSetOracle.sol";
import {WOTS, MerkleOTS} from "./lib/WOTS.sol";
import {AttestorSet} from "./lib/AttestorSet.sol";

/// @title StakeAttestationVerifier — Phase 1 implementation of IAttestationVerifier
/// @notice Verifies that an M-of-N quorum of QUANTOS-FINALIZED attestors each
/// produced a valid hash-based (Winternitz) one-time attestation over the
/// authorization digest. All on-chain work is keccak256 hashing — quantum-safe
/// and cheap.
///
/// ## Where the trust comes from (the QTS anchor)
/// The attestors are NOT a local registry. They are the Quantos L1 validator
/// set — staking QTS, slashed in QTS on Quantos. Their membership + WOTS roots
/// are finalized by Quantos consensus and delivered here via an L0 finality
/// proof, surfaced by {IAttestorSetOracle}. Each proof therefore carries a
/// Merkle inclusion path proving the attestor belongs to that finalized set.
///
/// The expensive SPHINCS+/SLH-DSA verification happens OFF-CHAIN inside each
/// attestor (see the SDK). On-chain we never see the SPHINCS+ signature at all.
///
/// @dev Pure validator: reads the finalized set root from the oracle and
/// recomputes hashes. No per-tx state, so {verifyAuthorization} stays `view`
/// and a Phase-2 ZK-STARK verifier can replace it behind the same interface
/// without touching PQCGuardAccount. POC / TESTNET ONLY. // AUDIT REQUIRED.
contract StakeAttestationVerifier is IAttestationVerifier {
    /// @notice Source of the Quantos-finalized attestor set (fed by L0 proofs).
    IAttestorSetOracle public immutable oracle;

    /// @notice One attestor's contribution to the quorum.
    /// @param attestorId Quantos validator id (32-byte address) — distinctness key.
    /// @param wotsRoot   The attestor's committed Winternitz tree root.
    /// @param leafIndex  Which one-time leaf of `wotsRoot` was used.
    /// @param wotsSig    67-element Winternitz signature over the digest.
    /// @param merklePath Path proving the WOTS key is leaf[leafIndex] of wotsRoot.
    /// @param setIndex   Index of this attestor's leaf in the finalized set tree.
    /// @param setProof   Path proving {attestorId, wotsRoot} ∈ finalized set root.
    struct AttestorProof {
        bytes32 attestorId;
        bytes32 wotsRoot;
        uint256 leafIndex;
        bytes32[] wotsSig;
        bytes32[] merklePath;
        uint256 setIndex;
        bytes32[] setProof;
    }

    error NoQuorum(uint256 valid, uint256 required);

    constructor(IAttestorSetOracle _oracle) {
        oracle = _oracle;
    }

    /// @inheritdoc IAttestationVerifier
    function authorizationDigest(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) public view returns (bytes32) {
        // Binds: pqc key (account), call, nonce, and chain. // AUDIT REQUIRED
        return keccak256(
            abi.encode(account, to, value, keccak256(data), nonce, block.chainid)
        );
    }

    /// @inheritdoc IAttestationVerifier
    /// @dev Decodes `attestation` as `AttestorProof[]`. For each DISTINCT
    /// attestor it checks three things, all by keccak hashing:
    ///   1. the WOTS signature recomputes to a leaf of the attestor's `wotsRoot`;
    ///   2. `{attestorId, wotsRoot}` is a member of the Quantos-finalized set
    ///      root reported by the oracle (the QTS anchor);
    ///   3. the signature is over exactly this authorization digest.
    /// Returns true iff the count of valid, distinct attestors reaches the
    /// quorum threshold the oracle reports from Quantos governance.
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
        uint256 threshold = oracle.threshold();
        bytes32 setRoot = oracle.attestorSetRoot();

        uint256 valid = 0;
        // Track distinct attestor ids (small N → linear scan is fine and cheap).
        bytes32[] memory seen = new bytes32[](proofs.length);
        uint256 seenLen = 0;

        for (uint256 i = 0; i < proofs.length; i++) {
            AttestorProof memory p = proofs[i];

            // Reject duplicate attestor entries (no double-counting one signer).
            if (_contains(seen, seenLen, p.attestorId)) continue;

            // (1) WOTS public key from the signature over THIS digest, and it
            //     must be a leaf of the attestor's committed wotsRoot.
            bytes32 wotsPub = WOTS.pubKeyFromSig(digest, p.wotsSig);
            bytes32 treeRoot = MerkleOTS.rootFromLeaf(
                MerkleOTS.leaf(wotsPub), p.leafIndex, p.merklePath
            );
            if (treeRoot != p.wotsRoot) continue;

            // (2) The attestor (id + wotsRoot) must be in the Quantos-finalized
            //     set delivered by the L0 proof. THIS is the QTS anchor.
            bytes32 attestorLeaf = AttestorSet.leaf(p.attestorId, p.wotsRoot);
            bytes32 recomputedSetRoot = MerkleOTS.rootFromLeaf(
                attestorLeaf, p.setIndex, p.setProof
            );
            if (recomputedSetRoot != setRoot) continue;

            seen[seenLen] = p.attestorId;
            seenLen += 1;
            valid += 1;

            if (valid >= threshold) return true; // early exit once quorum met
        }

        return valid >= threshold;
    }

    function _contains(bytes32[] memory arr, uint256 len, bytes32 x)
        private
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == x) return true;
        }
        return false;
    }
}
