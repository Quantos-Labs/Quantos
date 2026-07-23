// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @title AttestorSet — leaf encoding for the Quantos-finalized attestor set
/// @notice The attestor set is a Merkle tree whose leaves commit to each
/// Quantos validator's identity and WOTS root. The SAME encoding is recomputed
/// on Quantos L1 (Rust, `l0/pqc_guard.rs`) so the root matches bit-for-bit.
/// @dev keccak256 throughout for EVM/Rust parity. // AUDIT REQUIRED
library AttestorSet {
    /// @notice Leaf for an attestor: binds Quantos validator id + WOTS root.
    /// @param attestorId 32-byte Quantos validator address.
    /// @param wotsRoot   That validator's committed Winternitz tree root.
    function leaf(bytes32 attestorId, bytes32 wotsRoot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("PQCG_ATTESTOR_LEAF", attestorId, wotsRoot));
    }
}
