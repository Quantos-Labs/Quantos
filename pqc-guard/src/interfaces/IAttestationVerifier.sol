// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @title IAttestationVerifier
/// @notice THE most important architectural seam of PQC-Guard.
///
/// @dev `PQCGuardAccount` calls ONLY this interface to authorize a transaction.
/// It knows nothing about *how* the post-quantum authorization is proven. This
/// lets us swap the implementation WITHOUT touching the account:
///
///   Phase 1 (this MVP): `StakeAttestationVerifier`
///       - An M-of-N quorum of staked attestors verify the SPHINCS+/SLH-DSA
///         signature OFF-CHAIN, then each emits a hash-based one-time
///         (Winternitz) attestation. On-chain we only re-hash (keccak) — cheap
///         and itself quantum-safe.
///
///   Phase 2 (future, documented in README): `ZkStarkVerifier`
///       - A single succinct STARK proof attests that the SPHINCS+ verification
///         relation holds. The account contract is byte-for-byte unchanged; only
///         the address stored in `attestationVerifier` differs.
///
/// The verifier is intentionally a `view` function:
///   - It performs PURE cryptographic validation (no state mutation).
///   - Replay protection is the ACCOUNT's job via its monotonic `nonce`, which
///     is bound into the attested message. This keeps the seam minimal so any
///     Phase-2 verifier can satisfy it without bespoke storage.
interface IAttestationVerifier {
    /// @notice Returns true iff the supplied `attestation` proves that the
    /// post-quantum key authority behind `account` authorized exactly the call
    /// `(to, value, data)` at the given `nonce` on the current chain.
    ///
    /// @param account   The account identity. PQC-Guard uses the account's
    ///                   `pqcCommitment` (= keccak256 of the SLH-DSA public key)
    ///                   so the attestation is cryptographically bound to the
    ///                   specific post-quantum key.
    /// @param to        Target address of the authorized call.
    /// @param value     ETH value of the authorized call.
    /// @param data      Calldata of the authorized call.
    /// @param nonce     The account's current nonce (anti-replay).
    /// @param attestation Implementation-specific proof bytes. For Phase 1 this
    ///                   is an ABI-encoded array of Winternitz attestor proofs.
    /// @return ok       True iff the authorization is valid.
    function verifyAuthorization(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes calldata attestation
    ) external view returns (bool ok);

    /// @notice The exact message digest that authorities must sign/attest.
    /// @dev Exposed so SDKs and Phase-2 verifiers agree on the canonical digest.
    /// MUST bind: account (pqcCommitment), to, value, keccak256(data), nonce,
    /// and block.chainid — preventing cross-account and cross-chain replay.
    function authorizationDigest(
        bytes32 account,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) external view returns (bytes32 digest);
}
