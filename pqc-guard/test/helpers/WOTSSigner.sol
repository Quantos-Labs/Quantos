// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {WOTS, MerkleOTS} from "../../src/lib/WOTS.sol";

/// @title WOTSSigner — TEST-ONLY Winternitz signer + Merkle tree builder
/// @notice Mirrors {WOTS} and {MerkleOTS} so Foundry tests can produce valid
/// attestations without the off-chain TypeScript SDK. Deterministic from a seed.
/// @dev TEST ONLY. Secret keys are derived from a public seed — NEVER do this
/// outside tests. // AUDIT REQUIRED (mirror must match the on-chain verifier).
contract WOTSSigner {
    uint256 internal constant W = 16;
    uint256 internal constant LEN = 67;

    /// @notice Derive WOTS secret element i for a given (seed, leafIndex).
    function sk(bytes32 seed, uint256 leafIndex, uint256 chainIndex) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("PQCG_WOTS_SK", seed, leafIndex, chainIndex));
    }

    /// @notice Compressed WOTS public key for a leaf (top of every hash chain).
    function wotsPubKey(bytes32 seed, uint256 leafIndex) public pure returns (bytes32) {
        bytes32[] memory ends = new bytes32[](LEN);
        for (uint256 i = 0; i < LEN; i++) {
            bytes32 x = sk(seed, leafIndex, i);
            for (uint256 j = 0; j < W - 1; j++) {
                x = keccak256(abi.encodePacked(x));
            }
            ends[i] = x;
        }
        return keccak256(abi.encodePacked(ends));
    }

    /// @notice Produce a WOTS signature over `digest` for (seed, leafIndex).
    function sign(bytes32 seed, uint256 leafIndex, bytes32 digest)
        public
        pure
        returns (bytes32[] memory sig)
    {
        uint8[67] memory d = WOTS.digits(digest);
        sig = new bytes32[](LEN);
        for (uint256 i = 0; i < LEN; i++) {
            bytes32 x = sk(seed, leafIndex, i);
            // signature element = H^{d_i}(sk_i)
            for (uint256 j = 0; j < uint256(d[i]); j++) {
                x = keccak256(abi.encodePacked(x));
            }
            sig[i] = x;
        }
    }

    /// @notice Build a full Merkle tree of `2**height` WOTS leaves and return its root.
    function buildRoot(bytes32 seed, uint256 height) public pure returns (bytes32 root) {
        uint256 n = 1 << height;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 j = 0; j < n; j++) {
            level[j] = MerkleOTS.leaf(wotsPubKey(seed, j));
        }
        while (level.length > 1) {
            uint256 half = level.length / 2;
            bytes32[] memory next = new bytes32[](half);
            for (uint256 j = 0; j < half; j++) {
                next[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
            level = next;
        }
        root = level[0];
    }

    /// @notice Merkle authentication path (siblings) for a given leaf index.
    function authPath(bytes32 seed, uint256 height, uint256 index)
        public
        pure
        returns (bytes32[] memory path)
    {
        uint256 n = 1 << height;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 j = 0; j < n; j++) {
            level[j] = MerkleOTS.leaf(wotsPubKey(seed, j));
        }
        path = new bytes32[](height);
        uint256 idx = index;
        for (uint256 h = 0; h < height; h++) {
            uint256 sibling = idx ^ 1;
            path[h] = level[sibling];

            uint256 half = level.length / 2;
            bytes32[] memory next = new bytes32[](half);
            for (uint256 j = 0; j < half; j++) {
                next[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
            level = next;
            idx >>= 1;
        }
    }

    // ── Generic index-based Merkle over arbitrary leaves (the attestor set) ──
    // Mirrors AttestorSet root construction in Rust: pad to next power of two
    // with bytes32(0), then keccak(left,right) up the tree.

    function _padPow2(bytes32[] memory leaves) internal pure returns (bytes32[] memory padded) {
        uint256 cap = 1;
        while (cap < leaves.length) {
            cap <<= 1;
        }
        padded = new bytes32[](cap);
        for (uint256 i = 0; i < leaves.length; i++) {
            padded[i] = leaves[i];
        }
        // remaining entries are bytes32(0) by default
    }

    /// @notice Merkle root over arbitrary leaves (power-of-two zero padded).
    function merkleRoot(bytes32[] memory leaves) public pure returns (bytes32) {
        bytes32[] memory level = _padPow2(leaves);
        while (level.length > 1) {
            uint256 half = level.length / 2;
            bytes32[] memory next = new bytes32[](half);
            for (uint256 j = 0; j < half; j++) {
                next[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
            level = next;
        }
        return level[0];
    }

    /// @notice Merkle authentication path for `index` over arbitrary leaves.
    function merklePath(bytes32[] memory leaves, uint256 index)
        public
        pure
        returns (bytes32[] memory path)
    {
        bytes32[] memory level = _padPow2(leaves);
        // height = log2(level.length)
        uint256 height = 0;
        uint256 c = level.length;
        while (c > 1) {
            c >>= 1;
            height += 1;
        }
        path = new bytes32[](height);
        uint256 idx = index;
        for (uint256 h = 0; h < height; h++) {
            path[h] = level[idx ^ 1];
            uint256 half = level.length / 2;
            bytes32[] memory next = new bytes32[](half);
            for (uint256 j = 0; j < half; j++) {
                next[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
            level = next;
            idx >>= 1;
        }
    }
}
