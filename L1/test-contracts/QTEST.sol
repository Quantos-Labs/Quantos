// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title QTEST — Quantos Testnet Faucet Token
/// @notice Unlimited supply ERC-20 token for testing on Quantos
/// @dev Anyone can mint 1 QTEST token per claim
contract QTEST {
    string public constant name = "Quantos Test Token";
    string public constant symbol = "QTEST";
    uint8 public constant decimals = 18;
    
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public lastClaim;
    
    uint256 public constant CLAIM_AMOUNT = 1000 * 10**18; // 1000 QTEST
    uint256 public constant CLAIM_COOLDOWN = 24 hours;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Claimed(address indexed claimer, uint256 amount);
    
    /// @notice Claim 1000 QTEST tokens (once per 24 hours)
    function claim() public returns (bool) {
        require(
            block.timestamp >= lastClaim[msg.sender] + CLAIM_COOLDOWN,
            "Claim cooldown active"
        );
        
        lastClaim[msg.sender] = block.timestamp;
        totalSupply += CLAIM_AMOUNT;
        balanceOf[msg.sender] += CLAIM_AMOUNT;
        
        emit Claimed(msg.sender, CLAIM_AMOUNT);
        emit Transfer(address(0), msg.sender, CLAIM_AMOUNT);
        
        return true;
    }
    
    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
    
    /// @notice Check time until next claim is available
    function timeUntilNextClaim(address user) public view returns (uint256) {
        uint256 nextClaim = lastClaim[user] + CLAIM_COOLDOWN;
        if (block.timestamp >= nextClaim) {
            return 0;
        }
        return nextClaim - block.timestamp;
    }
    
    /// @notice Check if user can claim now
    function canClaim(address user) public view returns (bool) {
        return block.timestamp >= lastClaim[user] + CLAIM_COOLDOWN;
    }
}
