// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WOTS — Winternitz One-Time Signature verification (keccak256-based)
/// @notice Quantum-safe, on-chain-cheap signature verification used by the
/// Phase-1 attestation layer. Security rests ONLY on the preimage/2nd-preimage
/// resistance of keccak256, which Grover's algorithm degrades by at most a
/// square-root factor — i.e. ~128-bit post-quantum security for a 256-bit hash.
///
/// @dev THIS IS A POC. // AUDIT REQUIRED across the whole library.
/// Hand-rolled hash-based crypto is acceptable here ONLY because:
///   1. It is built solely from keccak256 (no novel primitive).
///   2. @noble/post-quantum does not expose raw Winternitz, so it cannot be
///      reused; the SDK mirrors this exact construction.
/// Do NOT use on mainnet without a formal audit and parameter review.
///
/// ## Parameters (fixed for the MVP)
///   - Hash:        keccak256, n = 32 bytes
///   - Winternitz:  w = 16  (LOG_W = 4 bits per digit)
///   - Message:     256-bit digest → LEN1 = 64 base-16 digits
///   - Checksum:    LEN2 = 3 base-16 digits (max checksum 64*15 = 960 < 16^3)
///   - Total chains LEN = 67
///
/// A WOTS public key is the keccak256 of the 67 chain tops. The signature is 67
/// 32-byte values. Verification recomputes the chain tops by hashing each
/// signature element `(w-1 - digit)` more times, then compresses.
///
/// ## One-time property
/// Each WOTS key MUST sign at most one message. Reuse leaks the secret key and
/// enables forgery. We therefore embed each WOTS public key as a leaf of a
/// per-attestor Merkle tree (XMSS-style) and the AttestorRegistry slashes any
/// attestor that produces two valid signatures from the same leaf index.
library WOTS {
    uint256 internal constant W = 16;
    uint256 internal constant LOG_W = 4;
    uint256 internal constant LEN1 = 64; // message digits (256 / 4)
    uint256 internal constant LEN2 = 3; // checksum digits
    uint256 internal constant LEN = 67; // LEN1 + LEN2

    error BadSignatureLength(uint256 got, uint256 expected);

    /// @notice Recompute the compressed WOTS public key implied by `sig` over `digest`.
    /// @param digest The 32-byte message digest that was signed.
    /// @param sig    The 67-element Winternitz signature.
    /// @return wotsPub keccak256 of the 67 recomputed chain tops.
    /// @dev If `sig` is a valid signature for `digest` under some key K, the
    /// returned value equals K's compressed public key. An attacker cannot find
    /// a different (digest', sig') yielding the same public key without breaking
    /// keccak256 preimage resistance. // AUDIT REQUIRED
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
            // Walk the hash chain from position d[i] up to the top (W-1).
            for (uint256 j = uint256(d[i]); j < W - 1; j++) {
                x = keccak256(abi.encodePacked(x));
            }
            ends[i] = x;
        }

        wotsPub = keccak256(abi.encodePacked(ends));
    }

    /// @notice Expand a digest into 64 message digits + 3 checksum digits (base-16).
    /// @dev The signer (TypeScript SDK and the Solidity test helper) MUST use the
    /// exact same digit ordering and checksum encoding, otherwise verification
    /// fails. Ordering: for each byte, high nibble then low nibble; checksum is
    /// big-endian across 3 nibbles. // AUDIT REQUIRED
    function digits(bytes32 digest) internal pure returns (uint8[LEN] memory d) {
        uint256 csum = 0;
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(digest[i]);
            uint8 hi = b >> 4;
            uint8 lo = b & 0x0f;
            d[2 * i] = hi;
            d[2 * i + 1] = lo;
            // checksum accumulates (w-1 - digit) so truncating a chain is detectable
            csum += (W - 1 - uint256(hi));
            csum += (W - 1 - uint256(lo));
        }
        // 3 base-16 checksum digits, big-endian
        d[64] = uint8((csum >> 8) & 0x0f);
        d[65] = uint8((csum >> 4) & 0x0f);
        d[66] = uint8(csum & 0x0f);
    }
}

/// @title MerkleOTS — index-addressed Merkle membership over keccak256
/// @notice Proves that a WOTS public key is the leaf at a specific index of an
/// attestor's committed tree. Index-addressing (not sorted pairs) lets the
/// registry enforce the one-time property per leaf index.
/// @dev // AUDIT REQUIRED
library MerkleOTS {
    /// @notice Leaf encoding for a compressed WOTS public key.
    function leaf(bytes32 wotsPub) internal pure returns (bytes32) {
        // Domain-separated leaf hash.
        return keccak256(abi.encodePacked("PQCG_WOTS_LEAF", wotsPub));
    }

    /// @notice Recompute the Merkle root from a leaf, its index, and the path.
    /// @param leafHash   keccak leaf (see {leaf}).
    /// @param index      Leaf index (determines hashing order at each level).
    /// @param path       Sibling hashes from leaf level up to the root.
    /// @return root      The recomputed root; compare to the registered root.
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
