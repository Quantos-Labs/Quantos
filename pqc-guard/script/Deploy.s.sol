// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {AttestorRegistry, IERC20} from "../src/AttestorRegistry.sol";
import {QuantosAttestorOracle, IL0ProofRegistry} from "../src/QuantosAttestorOracle.sol";
import {StakeAttestationVerifier} from "../src/StakeAttestationVerifier.sol";
import {PQCGuardAccount} from "../src/PQCGuardAccount.sol";

/// @notice Testnet deployment script for PQC-Guard (Base Sepolia by default).
///
/// Usage:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url base_sepolia --broadcast -vvvv
///
/// Required env:
///   DEPLOYER_PRIVATE_KEY   testnet key
///   L0_VERIFIER            address of the deployed QuantosL0Verifier (the
///                          IL0ProofRegistry the oracle reads from). On a fresh
///                          testnet you may point this at a mock you control.
///   ATTESTOR_THRESHOLD     M in the M-of-N quorum (default 2)
///
/// TESTNET ONLY. // AUDIT REQUIRED before any production use.
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address l0Verifier = vm.envOr("L0_VERIFIER", address(0));
        uint256 threshold = vm.envOr("ATTESTOR_THRESHOLD", uint256(2));

        require(l0Verifier != address(0), "set L0_VERIFIER (QuantosL0Verifier address)");

        vm.startBroadcast(pk);

        // 1. Reference stake token + local attestor registry (Quantos-side logic
        //    mirror; production slashing in QTS happens on Quantos L1).
        MockERC20 stakeToken = new MockERC20();
        AttestorRegistry registry =
            new AttestorRegistry(IERC20(address(stakeToken)), 1 ether, threshold);

        // 2. The QTS anchor: oracle fed by Quantos L0 finality proofs.
        QuantosAttestorOracle oracle =
            new QuantosAttestorOracle(IL0ProofRegistry(l0Verifier), msg.sender);

        // 3. Phase-1 verifier reads the finalized attestor set from the oracle.
        StakeAttestationVerifier verifier = new StakeAttestationVerifier(oracle);

        // 4. A sample guarded account owned by the deployer (pre-migration).
        PQCGuardAccount account = new PQCGuardAccount(msg.sender);

        vm.stopBroadcast();

        console2.log("MockERC20 stake token:    ", address(stakeToken));
        console2.log("AttestorRegistry (ref):   ", address(registry));
        console2.log("QuantosAttestorOracle:    ", address(oracle));
        console2.log("StakeAttestationVerifier: ", address(verifier));
        console2.log("PQCGuardAccount (sample): ", address(account));
        console2.log("L0 verifier (oracle src): ", l0Verifier);
        console2.log("Quorum threshold (M):     ", threshold);
    }
}
