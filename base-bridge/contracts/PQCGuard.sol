// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PQCSignatureRegistry.sol";

/// @title PQCGuard
/// @notice Abstract contract that any dApp inherits to enforce PQC verification
/// as a first-class Solidity modifier — exactly like `onlyOwner`, but post-quantum.
///
/// @dev **Problem it solves**: without this, dApps that don't explicitly check
/// `pqcSecured` remain exposed even if the registry exists on-chain.
/// Inheriting `PQCGuard` and adding `pqcRequired(actionHash)` to sensitive
/// functions makes PQC enforcement mandatory and compiler-checked.
///
/// **Usage (new dApps)**:
/// ```solidity
/// contract MyDeFiVault is PQCGuard {
///     constructor(address registry) PQCGuard(registry) {}
///
///     function withdraw(uint256 amount, bytes32 actionHash)
///         external
///         pqcRequired(actionHash)   // ← Falcon-512 confirmed or revert
///     {
///         _processWithdrawal(msg.sender, amount);
///     }
/// }
/// ```
///
/// **Usage (existing contracts)**: deploy `PQCGatedProxy` in front — no code change needed.
abstract contract PQCGuard {
    PQCSignatureRegistry public immutable pqcRegistry;

    /// @notice Thrown when an actionHash has not been PQC-verified yet.
    error PqcNotSecured(bytes32 actionHash);
    /// @notice Thrown when the actor recorded in the action ≠ msg.sender.
    error PqcActorMismatch(bytes32 actionHash);
    /// @notice Thrown when the action does not exist in the registry.
    error PqcActionNotFound(bytes32 actionHash);

    constructor(address registry) {
        pqcRegistry = PQCSignatureRegistry(payable(registry));
    }

    /// @notice Require that `actionHash` is PQC-secured AND that the action's
    /// registered actor is msg.sender. Use this for user-specific sensitive functions.
    /// @param actionHash The keccak256(actor, payloadHash, nonce) from the registry.
    modifier pqcRequired(bytes32 actionHash) {
        _assertPqcSecured(actionHash, true);
        _;
    }

    /// @notice Require only that `actionHash` is PQC-secured (actor not checked).
    /// Use this for shared/protocol-level actions where the actor can be anyone.
    /// @param actionHash The keccak256(actor, payloadHash, nonce) from the registry.
    modifier pqcSecuredOnly(bytes32 actionHash) {
        _assertPqcSecured(actionHash, false);
        _;
    }

    function _assertPqcSecured(bytes32 actionHash, bool checkActor) internal view {
        if (!pqcRegistry.pqcSecured(actionHash)) revert PqcNotSecured(actionHash);
        if (checkActor) {
            (address actor,,,,,,) = pqcRegistry.pendingActions(actionHash);
            if (actor == address(0)) revert PqcActionNotFound(actionHash);
            if (actor != msg.sender) revert PqcActorMismatch(actionHash);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// @title PQCGatedProxy
/// @notice Transparent call proxy that enforces PQC verification for an arbitrary
/// existing target contract — no changes to the target's code required.
///
/// @dev **How it works**:
/// Instead of calling `target.someFunction(...)` directly, users call:
///   `proxy.forward(actionHash, abi.encodeCall(target.someFunction, (...)))`
///
/// The proxy verifies `pqcSecured[actionHash]` and `actor == msg.sender` before
/// forwarding the call. Reverts with exact revert data from target on failure.
///
/// **Deployment**:
/// 1. Deploy `PQCGatedProxy(registryAddress, targetAddress)`.
/// 2. Grant the proxy the same permissions the EOA had on target (if applicable).
/// 3. Point users / front-end to the proxy instead of target.
///
/// **Example**:
/// ```typescript
/// // SDK side
/// const actionHash = await registry.submitHybridAction(payloadHash, pqcSig, v, r, s);
/// // Wait for Quantos L0 to call verifyPqcSignature(actionHash)
/// await proxy.forward(actionHash, target.interface.encodeFunctionData("withdraw", [amount]));
/// ```
contract PQCGatedProxy {
    PQCSignatureRegistry public immutable registry;
    address public immutable target;

    error PqcNotSecured(bytes32 actionHash);
    error PqcActorMismatch(bytes32 actionHash);
    error ForwardFailed();

    event Forwarded(bytes32 indexed actionHash, address indexed actor, bytes4 selector);

    constructor(address _registry, address _target) {
        registry = PQCSignatureRegistry(payable(_registry));
        target = _target;
    }

    /// @notice Forward `data` to the target contract, gated behind PQC verification.
    /// @param actionHash A PQC-secured action hash from PQCSignatureRegistry.
    /// @param data ABI-encoded calldata for the target function.
    /// @return result Raw return bytes from the target call.
    function forward(
        bytes32 actionHash,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        // ── 1. PQC check ──
        if (!registry.pqcSecured(actionHash)) revert PqcNotSecured(actionHash);

        (address actor,,,,,,) = registry.pendingActions(actionHash);
        if (actor != msg.sender) revert PqcActorMismatch(actionHash);

        // ── 2. Emit before external call (CEI pattern) ──
        bytes4 sel = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        emit Forwarded(actionHash, msg.sender, sel);

        // ── 3. Forward to target ──
        bool ok;
        (ok, result) = target.call{value: msg.value}(data);
        if (!ok) {
            assembly { revert(add(result, 32), mload(result)) }
        }
    }

    /// @notice Accept ETH (for proxying payable calls).
    receive() external payable {}
}
