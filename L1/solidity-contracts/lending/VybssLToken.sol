// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title VybssLToken - Interest-bearing supply receipt token
/// @notice Minted 1:1 on supply, value grows via index. Non-rebasing, share-based.
contract VybssLToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    address public pool; // Only the lending pool can mint/burn
    address public underlyingAsset;

    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) public allowances;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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

    /// @notice Mint shares to user. Called by pool on supply.
    function mint(address to, uint256 shareAmount) external onlyPool {
        shares[to] += shareAmount;
        totalShares += shareAmount;
        emit Transfer(address(0), to, shareAmount);
    }

    /// @notice Burn shares from user. Called by pool on withdraw.
    function burn(address from, uint256 shareAmount) external onlyPool {
        require(shares[from] >= shareAmount, "Insufficient shares");
        shares[from] -= shareAmount;
        totalShares -= shareAmount;
        emit Transfer(from, address(0), shareAmount);
    }

    function balanceOf(address account) external view returns (uint256) {
        return shares[account];
    }

    function totalSupply() external view returns (uint256) {
        return totalShares;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(shares[msg.sender] >= amount, "Insufficient");
        shares[msg.sender] -= amount;
        shares[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(shares[from] >= amount, "Insufficient");
        require(allowances[from][msg.sender] >= amount, "Not approved");
        allowances[from][msg.sender] -= amount;
        shares[from] -= amount;
        shares[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return allowances[owner][spender];
    }
}
