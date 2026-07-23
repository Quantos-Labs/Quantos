// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title SQTEST - Stablecoin token for Quantos testnet
/// @notice ERC20 stablecoin minted/burned by SQTESTEngine only
contract SQTEST {
    string public constant name = "SQTEST Stablecoin";
    string public constant symbol = "SQTEST";
    uint8 public constant decimals = 18;
    
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    address public engine;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event EngineSet(address indexed engineAddress);
    
    constructor() {
    }

    function setEngine(address _engine) external {
        require(engine == address(0), "Engine already set");
        require(_engine != address(0), "Invalid engine");
        engine = _engine;
        emit EngineSet(_engine);
    }
    
    modifier onlyEngine() {
        require(msg.sender == engine, "Only engine");
        _;
    }
    
    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
    
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
    
    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= amount, "Insufficient allowance");
        unchecked {
            _approve(from, msg.sender, currentAllowance - amount);
        }
        _transfer(from, to, amount);
        return true;
    }
    
    function mint(address to, uint256 amount) external onlyEngine {
        require(to != address(0), "Mint to zero address");
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function burn(address from, uint256 amount) external onlyEngine {
        require(_balances[from] >= amount, "Insufficient balance");
        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
    
    function _transfer(address from, address to, uint256 amount) private {
        require(from != address(0), "Transfer from zero");
        require(to != address(0), "Transfer to zero");
        require(_balances[from] >= amount, "Insufficient balance");
        
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
    
    function _approve(address owner, address spender, uint256 amount) private {
        require(owner != address(0), "Approve from zero");
        require(spender != address(0), "Approve to zero");
        
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}
