// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IL0ProofRegistry} from "../../src/QuantosAttestorOracle.sol";

/// @notice TEST-ONLY mock of the Quantos L0 proof registry. Lets tests mark a
/// proof hash as "verified" without running the full PQC/STARK verification
/// that the real `QuantosL0Verifier` performs.
contract MockL0ProofRegistry is IL0ProofRegistry {
    mapping(bytes32 => bool) public verified;

    function setVerified(bytes32 proofHash, bool ok) external {
        verified[proofHash] = ok;
    }

    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return verified[proofHash];
    }
}
