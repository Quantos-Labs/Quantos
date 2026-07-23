// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

/// @title SimpleFlashReceiver
/// @notice Minimal flash loan receiver for testing.
///         Receives tokens from the pool, then transfers back amount + premium.
///         In production, a receiver would perform arbitrage, liquidation or other
///         profit-generating logic between receiving and repaying.
contract SimpleFlashReceiver is IFlashLoanReceiver {
    address public pool;

    constructor(address _pool) {
        pool = _pool;
    }

    /// @notice Called by the lending pool during a flash loan.
    ///         Must repay amount + premium and return true.
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address /* initiator */,
        bytes calldata /* params */
    ) external override returns (bool) {
        // --- Custom logic goes here (arbitrage, liquidation, etc.) ---

        // Repay principal + premium back to the pool
        uint256 repayAmount = amount + premium;
        require(
            IERC20(asset).transfer(pool, repayAmount),
            "Repay failed"
        );

        return true;
    }

    /// @notice Check this contract's balance for a given token
    function getBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
}
