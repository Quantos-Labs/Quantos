// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IVybssPool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function feeBps() external view returns (uint256);
    function sqrtPriceX64() external view returns (uint256);
    function reserve0() external view returns (uint256);
    function reserve1() external view returns (uint256);
    function liquidity() external view returns (uint256);
    function swap(bool zeroForOne, uint256 amountIn, uint256 priceLimitX64) external returns (uint256);
    function quote(bool zeroForOne, uint256 amountIn) external view returns (uint256);
    function mint(int256 tL, int256 tU, uint256 max0, uint256 max1) external returns (uint256, uint256, uint256);
    function burn(uint256 posId, uint256 liq) external returns (uint256, uint256);
    function collect(uint256 posId) external returns (uint256, uint256);
}

interface IVybssFactory {
    function getPool(address t0, address t1, uint256 fee) external view returns (address);
    function allPoolsLength() external view returns (uint256);
    function allPools(uint256 i) external view returns (address);
}

interface IERC20Router {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssRouter — Smart swap router across pools
/// @notice Finds best pool for a pair, supports multi-hop, slippage protection
contract VybssRouter {
    address public factory;
    uint256 constant Q64 = 1 << 64;

    // Fee tiers to search (in bps)
    uint256[4] public FEE_TIERS;

    constructor(address _factory) {
        factory = _factory;
        FEE_TIERS[0] = 1;
        FEE_TIERS[1] = 5;
        FEE_TIERS[2] = 30;
        FEE_TIERS[3] = 100;
    }

    /// @notice Swap exact input for maximum output, auto-selecting best pool
    function swapExactInput(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        (address bestPool, bool zeroForOne) = _findBestPool(tokenIn, tokenOut, amountIn);
        require(bestPool != address(0), "No pool");

        IERC20Router(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20Router(tokenIn).approve(bestPool, amountIn);

        uint256 limit = zeroForOne ? 1 : type(uint256).max - 1;
        amountOut = IVybssPool(bestPool).swap(zeroForOne, amountIn, limit);
        require(amountOut >= minAmountOut, "Slippage");

        IERC20Router(tokenOut).transferFrom(address(this), msg.sender, amountOut);
    }

    /// @notice Get best quote across all fee tiers
    function getQuote(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view returns (uint256 bestOut, address bestPool, uint256 bestFee) {
        for (uint256 i = 0; i < 4; i++) {
            address pool = IVybssFactory(factory).getPool(tokenIn, tokenOut, FEE_TIERS[i]);
            if (pool == address(0)) continue;
            if (IVybssPool(pool).liquidity() == 0) continue;

            bool zfo = IVybssPool(pool).token0() == tokenIn;
            uint256 out = IVybssPool(pool).quote(zfo, amountIn);
            if (out > bestOut) {
                bestOut = out;
                bestPool = pool;
                bestFee = FEE_TIERS[i];
            }
        }
    }

    /// @notice Add liquidity via router (handles approve flow)
    function addLiquidity(
        address pool,
        int256 tickLower,
        int256 tickUpper,
        uint256 amount0Max,
        uint256 amount1Max
    ) external returns (uint256 posId, uint256 used0, uint256 used1) {
        address t0 = IVybssPool(pool).token0();
        address t1 = IVybssPool(pool).token1();

        if (amount0Max > 0) {
            IERC20Router(t0).transferFrom(msg.sender, address(this), amount0Max);
            IERC20Router(t0).approve(pool, amount0Max);
        }
        if (amount1Max > 0) {
            IERC20Router(t1).transferFrom(msg.sender, address(this), amount1Max);
            IERC20Router(t1).approve(pool, amount1Max);
        }

        (posId, used0, used1) = IVybssPool(pool).mint(tickLower, tickUpper, amount0Max, amount1Max);

        // Refund unused tokens
        if (amount0Max > used0) {
            IERC20Router(t0).transferFrom(address(this), msg.sender, amount0Max - used0);
        }
        if (amount1Max > used1) {
            IERC20Router(t1).transferFrom(address(this), msg.sender, amount1Max - used1);
        }
    }

    function _findBestPool(address tIn, address tOut, uint256 amtIn)
        private view returns (address best, bool zfo)
    {
        uint256 bestOut = 0;
        for (uint256 i = 0; i < 4; i++) {
            address pool = IVybssFactory(factory).getPool(tIn, tOut, FEE_TIERS[i]);
            if (pool == address(0)) continue;
            if (IVybssPool(pool).liquidity() == 0) continue;
            bool z = IVybssPool(pool).token0() == tIn;
            uint256 out = IVybssPool(pool).quote(z, amtIn);
            if (out > bestOut) {
                bestOut = out;
                best = pool;
                zfo = z;
            }
        }
    }
}
