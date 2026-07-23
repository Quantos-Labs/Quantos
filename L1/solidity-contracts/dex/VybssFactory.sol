// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title VybssFactory — Registers liquidity pools with fee tiers
contract VybssFactory {
    address public owner;
    mapping(uint256 => bool) public feeEnabled;
    mapping(address => mapping(address => mapping(uint256 => address))) public getPool;
    address[] public allPools;

    struct PoolInfo { address token0; address token1; uint256 feeBps; address pool; }
    PoolInfo[] public poolInfos;

    event PoolCreated(address indexed token0, address indexed token1, uint256 feeBps, address pool, uint256 cnt);
    event FeeTierEnabled(uint256 feeBps);

    constructor() {
        owner = msg.sender;
        feeEnabled[1]   = true;
        feeEnabled[5]   = true;
        feeEnabled[30]  = true;
        feeEnabled[100] = true;
    }

    function registerPool(address t0, address t1, uint256 feeBps, address pool) external {
        require(t0 != t1 && pool != address(0), "bad");
        require(feeEnabled[feeBps], "fee");
        (address a, address b) = t0 < t1 ? (t0, t1) : (t1, t0);
        require(getPool[a][b][feeBps] == address(0), "exists");
        getPool[a][b][feeBps] = pool;
        getPool[b][a][feeBps] = pool;
        allPools.push(pool);
        poolInfos.push(PoolInfo(a, b, feeBps, pool));
        emit PoolCreated(a, b, feeBps, pool, allPools.length);
    }

    function allPoolsLength() external view returns (uint256) { return allPools.length; }

    function getPoolInfo(uint256 i) external view returns (address, address, uint256, address) {
        PoolInfo memory p = poolInfos[i];
        return (p.token0, p.token1, p.feeBps, p.pool);
    }

    function enableFeeTier(uint256 bps) external {
        require(msg.sender == owner, "!owner");
        feeEnabled[bps] = true;
        emit FeeTierEnabled(bps);
    }
}
