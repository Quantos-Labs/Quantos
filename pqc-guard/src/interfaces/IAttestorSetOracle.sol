// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAttestorSetOracle
/// @notice The bridge that makes Quantos NON-OPTIONAL to PQC-Guard.
///
/// The set of attestors is NOT a local EVM registry. It IS the Quantos L1
/// validator set: validators stake QTS and are slashed in QTS on Quantos.
/// Their membership + WOTS commitment roots are finalized by Quantos consensus
/// (post-quantum) and exported to this chain inside an L0 finality proof.
///
/// This oracle exposes the latest FINALIZED attestor-set commitment that the
/// `StakeAttestationVerifier` checks membership against. Economic security of
/// the whole PQC-Guard system therefore equals the QTS staked behind Quantos —
/// the EigenLayer-style anchor.
///
/// @dev The commitment is a Merkle root over leaves
///   keccak256("PQCG_ATTESTOR_LEAF", attestorId, wotsRoot)
/// where `attestorId` is the 32-byte Quantos validator address and `wotsRoot`
/// is that validator's committed Winternitz tree root.
interface IAttestorSetOracle {
    /// @notice Latest finalized attestor-set Merkle root (sourced from Quantos L0).
    function attestorSetRoot() external view returns (bytes32);

    /// @notice Quantos epoch the current root corresponds to (monotonic).
    function attestorEpoch() external view returns (uint64);

    /// @notice M in the M-of-N quorum, as decided by Quantos governance.
    function threshold() external view returns (uint256);
}
