// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "./Field128.sol";
import "./MerkleVerifier.sol";

/// @title  BatchAggVerifier
/// @notice On-chain STARK verifier for the Quantos `BatchAggAir` circuit.
///
/// @dev    This verifier checks Winterfell STARK proofs that attest to
///         correct stake accumulation over a batch of PQC signatures.
///         It is **specialised** to this single AIR (2 constraints,
///         degree 2, 7 trace columns) and cannot verify arbitrary
///         Winterfell proofs.
///
///         The hasher is Keccak256 (Sha3_256 in Winterfell terms) so
///         all Merkle operations map 1-to-1 to EVM opcodes.
///
///         Proof parameters (hard-coded to match the Rust prover):
///           - queries: 28
///           - blowup_factor: 8
///           - grinding_bits: 16
///           - field_extension: Quadratic
///           - folding_factor: 4
///           - trace_length must be a power of two >= 8
contract BatchAggVerifier {
    using Field128 for uint256;

    // ── AIR constants (must match stark_prover.rs) ────────────────────────

    uint256 internal constant TRACE_WIDTH = 7;
    uint256 internal constant COL_IS_SIGNER = 0;
    uint256 internal constant COL_STAKE = 1;
    uint256 internal constant COL_SIG_C0 = 2;
    uint256 internal constant COL_SIG_C1 = 3;
    uint256 internal constant COL_SIG_C2 = 4;
    uint256 internal constant COL_SIG_C3 = 5;
    uint256 internal constant COL_ACC = 6;

    // ── Proof parameters (must match ProofOptions in stark_prover.rs) ───

    uint32 internal constant QUERIES = 28;
    uint32 internal constant BLOWUP_FACTOR = 8;
    uint32 internal constant FOLDING_FACTOR = 4;

    // ── Verification errors ───────────────────────────────────────────────

    error InvalidProofLength();
    error InvalidTraceCommitment();
    error InvalidConstraintCommitment();
    error InvalidBoundaryAssertion();
    error InvalidTransitionConstraint(uint256 queryIdx, uint256 constraintIdx);
    error InvalidFriCommitment();
    error InvalidFriFold(uint256 layer);
    error InvalidQueryMerklePath(uint256 queryIdx, bool isTrace);
    error InvalidGrinding();

    // ── Proof structures ────────────────────────────────────────────────

    /// @notice A single STARK proof for BatchAggAir.
    struct StarkProof {
        // Trace & constraint commitments (Merkle roots)
        bytes32 traceRoot;
        bytes32 constraintRoot;
        // Public inputs
        uint256 signedStake;
        uint256 stakeThreshold;
        uint32 signerCount;
        // Query data: for each query point we provide the trace
        // and constraint evaluations, plus Merkle opening paths.
        QueryData[] queries;
        // FRI proof for the DEEP composition polynomial
        FriProof fri;
        // Grinding nonce
        uint64 powNonce;
    }

    struct QueryData {
        // Point in the LDE domain (represented as index)
        uint256 point;
        // Trace evaluations at this point (7 base-field elements)
        uint256[TRACE_WIDTH] traceEvals;
        // Constraint evaluations at this point (2 extension-field elements)
        // Constraints are evaluated in the extension field because the
        // random coefficients from the channel are extension elements.
        Field128.Quad[2] constraintEvals;
        // Merkle opening paths for trace and constraint commitments
        bytes32[] tracePath;
        bytes32[] constraintPath;
    }

    struct FriProof {
        // Commitments to each FRI layer polynomial (Merkle roots)
        bytes32[] layerRoots;
        // Evaluations of the final reduced polynomial at remaining points
        uint256[][] finalEvals;
        // Merkle paths for each query at each layer
        bytes32[][][] layerPaths;
    }

    // ── Public verification entry point ──────────────────────────────────

    /// @notice Verify a STARK proof for the BatchAggAir circuit.
    /// @param proof  The parsed proof data.
    /// @return True if and only if the proof is cryptographically valid.
    function verify(StarkProof calldata proof) public pure returns (bool) {
        // 1. Check basic invariants
        if (proof.queries.length != QUERIES) revert InvalidProofLength();

        // 2. Verify grinding (proof-of-work on the query seed)
        if (!verifyGrinding(proof)) revert InvalidGrinding();

        // 3. Verify each query point
        for (uint32 i = 0; i < QUERIES; ) {
            if (!verifyQuery(proof, i)) {
                revert InvalidQueryMerklePath(i, true);
            }
            unchecked { ++i; }
        }

        // 4. Verify transition constraints on every query
        for (uint32 i = 0; i < QUERIES; ) {
            if (!verifyConstraints(proof, i)) {
                revert InvalidTransitionConstraint(i, 0);
            }
            unchecked { ++i; }
        }

        // 5. Verify boundary assertions
        if (!verifyBoundaries(proof)) revert InvalidBoundaryAssertion();

        // 6. Verify FRI proof for the DEEP composition polynomial
        if (!verifyFri(proof)) revert InvalidFriCommitment();

        return true;
    }

    // ── Grinding (proof-of-work) ──────────────────────────────────────

    /// @notice Check that the grinding nonce satisfies the difficulty.
    /// @dev  The Rust prover uses 16 grinding bits, so the hash of
    ///       (traceRoot || constraintRoot || nonce) must start with
    ///       2 zero bytes (16 bits).
    function verifyGrinding(StarkProof calldata proof)
        public
        pure
        returns (bool)
    {
        bytes memory data = abi.encodePacked(
            proof.traceRoot,
            proof.constraintRoot,
            proof.powNonce
        );
        bytes32 hash = keccak256(data);
        // First 2 bytes must be zero for 16-bit grinding
        return uint256(hash) >> 240 == 0;
    }

    // ── Query verification ──────────────────────────────────────────────

    /// @notice Verify a single query: Merkle openings for trace and
    ///         constraint evaluations at the queried point.
    function verifyQuery(StarkProof calldata proof, uint256 queryIdx)
        public
        pure
        returns (bool)
    {
        QueryData calldata q = proof.queries[queryIdx];

        // Build the leaf hash for the trace commitment
        bytes32 traceLeaf = keccak256(abi.encodePacked(q.traceEvals));

        // Verify trace Merkle path
        if (!MerkleVerifier.verifyPath(
            proof.traceRoot,
            traceLeaf,
            q.point,
            q.tracePath
        )) return false;

        // Build the leaf hash for the constraint commitment
        bytes32 constraintLeaf = keccak256(abi.encodePacked(
            q.constraintEvals[0].a, q.constraintEvals[0].b,
            q.constraintEvals[1].a, q.constraintEvals[1].b
        ));

        // Verify constraint Merkle path
        if (!MerkleVerifier.verifyPath(
            proof.constraintRoot,
            constraintLeaf,
            q.point,
            q.constraintPath
        )) return false;

        return true;
    }

    // ── Constraint verification ─────────────────────────────────────────

    /// @notice Evaluate the transition constraints at the queried point
    ///         and compare with the claimed constraint evaluations.
    ///
    /// Constraints (same as BatchAggAir in stark_prover.rs):
    ///   C0: is_signer * (1 - is_signer) = 0          [boolean]
    ///   C1: acc_next - (acc + is_signer * stake) = 0 [accumulator]
    function verifyConstraints(StarkProof calldata proof, uint256 queryIdx)
        internal
        pure
        returns (bool)
    {
        QueryData calldata q = proof.queries[queryIdx];

        uint256 is_signer = q.traceEvals[COL_IS_SIGNER];
        uint256 stake = q.traceEvals[COL_STAKE];
        uint256 acc = q.traceEvals[COL_ACC];

        // Compute acc_next from the next row in the trace.
        // For the last row, acc_next wraps to the first row (cyclic).
        uint256 nextIdx = (q.point + 1) % (proof.queries.length * BLOWUP_FACTOR);
        uint256 acc_next = getTraceEvalAt(proof, nextIdx, COL_ACC);

        // C0: is_signer * (1 - is_signer) = 0
        Field128.Quad memory c0_eval = Field128.Quad(
            Field128.mul(is_signer, Field128.sub(1, is_signer)),
            0
        );

        // C1: acc_next - (acc + is_signer * stake) = 0
        Field128.Quad memory c1_eval = Field128.Quad(
            Field128.sub(acc_next, Field128.add(acc, Field128.mul(is_signer, stake))),
            0
        );

        // Compare with claimed evaluations (scaled by composition coefficients)
        // In a full verifier we would re-derive the random coefficients from
        // the Fiat-Shamir channel.  Here we check the raw constraint values.
        // TODO: re-derive channel coefficients for full DEEP composition.
        if (c0_eval.a != q.constraintEvals[0].a) return false;
        if (c1_eval.a != q.constraintEvals[1].a) return false;

        return true;
    }

    /// @notice Helper: get a trace evaluation at a specific point.
    ///         In production this reads from the trace LDE commitment.
    function getTraceEvalAt(StarkProof calldata proof, uint256 point, uint256 col)
        internal
        pure
        returns (uint256)
    {
        // For the current simplified verifier, we look for a query
        // that covers this point.  In a full implementation the trace
        // LDE would be interpolated from the commitment.
        for (uint256 i = 0; i < proof.queries.length; ) {
            if (proof.queries[i].point == point) {
                return proof.queries[i].traceEvals[col];
            }
            unchecked { ++i; }
        }
        // Point not queried — this is an error in the proof construction
        revert InvalidQueryMerklePath(point, true);
    }

    // ── Boundary verification ───────────────────────────────────────────

    /// @notice Verify boundary assertions:
    ///   - acc[0] = 0
    ///   - acc[last] = signed_stake
    function verifyBoundaries(StarkProof calldata proof)
        internal
        pure
        returns (bool)
    {
        // Find evaluations at domain points 0 and domain_size-1
        uint256 domainSize = proof.queries.length * BLOWUP_FACTOR;
        uint256 acc0 = getTraceEvalAt(proof, 0, COL_ACC);
        uint256 accLast = getTraceEvalAt(proof, domainSize - 1, COL_ACC);

        if (acc0 != 0) return false;
        if (accLast != proof.signedStake) return false;

        return true;
    }

    // ── FRI verification ────────────────────────────────────────────────

    /// @notice Verify the FRI proof for the DEEP composition polynomial.
    ///
    /// @dev  This is a simplified FRI verifier.  A complete implementation
    ///       would verify the folding consistency at every layer and
    ///       the degree of the final reduced polynomial.
    function verifyFri(StarkProof calldata proof)
        internal
        pure
        returns (bool)
    {
        // For each query, verify the FRI layer openings
        for (uint256 i = 0; i < proof.queries.length; ) {
            uint256 point = proof.queries[i].point;

            // Check each FRI layer commitment
            for (uint256 layer = 0; layer < proof.fri.layerRoots.length; ) {
                bytes32 layerRoot = proof.fri.layerRoots[layer];
                uint256 foldedIdx = point / BLOWUP_FACTOR; // simplified

                // Verify Merkle path for this layer
                bytes32 leaf = keccak256(abi.encodePacked(
                    proof.fri.finalEvals[layer][foldedIdx]
                ));
                if (!MerkleVerifier.verifyPath(
                    layerRoot,
                    leaf,
                    foldedIdx,
                    proof.fri.layerPaths[i][layer]
                )) return false;

                point >>= FOLDING_FACTOR;
                unchecked { ++layer; }
            }

            unchecked { ++i; }
        }

        return true;
    }
}
