// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  MerkleVerifier
/// @notice Helper for verifying Merkle inclusion proofs using keccak256.
///
/// @dev    This matches the Merkle tree construction used by Winterfell
///         when configured with Sha3_256 (which is keccak256 in EVM).
library MerkleVerifier {
    /// @notice Verify a Merkle path.
    /// @param root   The expected Merkle root.
    /// @param leaf   The leaf hash.
    /// @param index  The leaf index (0-based, from left to right).
    /// @param path   Sibling hashes from leaf to root.
    /// @return True if the path proves `leaf` is at `index` under `root`.
    function verifyPath(
        bytes32 root,
        bytes32 leaf,
        uint256 index,
        bytes32[] memory path
    ) internal pure returns (bool) {
        bytes32 current = leaf;
        for (uint256 i = 0; i < path.length; ) {
            if (index & 1 == 0) {
                current = keccak256(abi.encodePacked(current, path[i]));
            } else {
                current = keccak256(abi.encodePacked(path[i], current));
            }
            index >>= 1;
            unchecked { ++i; }
        }
        return current == root;
    }

    /// @notice Batch-verify many Merkle paths against the same root.
    /// @return True if ALL paths are valid.
    function verifyBatch(
        bytes32 root,
        bytes32[] memory leaves,
        uint256[] memory indices,
        bytes32[][] memory paths
    ) internal pure returns (bool) {
        require(
            leaves.length == indices.length && leaves.length == paths.length,
            "MerkleVerifier: length mismatch"
        );
        for (uint256 i = 0; i < leaves.length; ) {
            if (!verifyPath(root, leaves[i], indices[i], paths[i])) {
                return false;
            }
            unchecked { ++i; }
        }
        return true;
    }
}
