// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title VybssDebtToken - Non-transferable debt tracking token
/// @notice Tracks borrow positions. Only the lending pool can mint/burn.
contract VybssDebtToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    address public pool;
    address public underlyingAsset;

    uint256 public totalDebtShares;
    mapping(address => uint256) public debtShares;

    event Transfer(address indexed from, address indexed to, uint256 value);

    modifier onlyPool() {
        require(msg.sender == pool, "Only pool");
        _;
    }

    constructor(string memory _name, string memory _symbol, address _pool, address _underlying) {
        name = _name;
        symbol = _symbol;
        pool = _pool;
        underlyingAsset = _underlying;
    }

    /// @notice Mint debt shares when user borrows
    function mint(address to, uint256 amount) external onlyPool {
        debtShares[to] += amount;
        totalDebtShares += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @notice Burn debt shares when user repays
    function burn(address from, uint256 amount) external onlyPool {
        require(debtShares[from] >= amount, "Exceeds debt");
        debtShares[from] -= amount;
        totalDebtShares -= amount;
        emit Transfer(from, address(0), amount);
    }

    function balanceOf(address account) external view returns (uint256) {
        return debtShares[account];
    }

    function totalSupply() external view returns (uint256) {
        return totalDebtShares;
    }

    // Debt tokens are non-transferable
    function transfer(address, uint256) external pure returns (bool) {
        revert("Debt not transferable");
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        revert("Debt not transferable");
    }

    function approve(address, uint256) external pure returns (bool) {
        revert("Debt not transferable");
    }
}
