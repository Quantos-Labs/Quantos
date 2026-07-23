// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title insQTEST
/// @notice ERC-20 receipt token issued to underwriters who deposit stQTEST into VybssInsurancePool.
contract insQTEST {
    string public constant name = "Insured stQTEST";
    string public constant symbol = "insQTEST";
    uint8 public constant decimals = 18;

    address public owner;
    address public manager; // VybssInsurancePool

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner_, address indexed spender, uint256 value);
    event ManagerUpdated(address indexed manager);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyManager() { require(msg.sender == manager, "not manager"); _; }

    constructor() {
        owner = msg.sender;
    }

    function setManager(address _manager) external onlyOwner {
        manager = _manager;
        emit ManagerUpdated(_manager);
    }

    function totalSupply() external view returns (uint256) { return _totalSupply; }
    function balanceOf(address account) external view returns (uint256) { return _balances[account]; }
    function allowance(address owner_, address spender) external view returns (uint256) { return _allowances[owner_][spender]; }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(_balances[msg.sender] >= amount, "insufficient");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(_balances[from] >= amount, "insufficient");
        require(_allowances[from][msg.sender] >= amount, "allowance");
        _balances[from] -= amount;
        _allowances[from][msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external onlyManager {
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external onlyManager {
        require(_balances[from] >= amount, "insufficient");
        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}
