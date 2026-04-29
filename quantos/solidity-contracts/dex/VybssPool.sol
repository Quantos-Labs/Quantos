// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Pool {
    function balanceOf(address a) external view returns (uint256);
    function transfer(address to, uint256 v) external returns (bool);
    function transferFrom(address f, address t, uint256 v) external returns (bool);
}

/// @title VybssPool — Concentrated-liquidity AMM pool for Quantos
/// @notice One pool per (token0, token1, feeTier). 100% fees to LPs.
contract VybssPool {
    address public factory;
    address public token0;
    address public token1;
    uint256 public feeBps;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public liquidity;        // active in-range liquidity

    uint256 public sqrtPriceX64;     // sqrt(token1/token0) * 2^64
    int256  public currentTick;

    // Dynamic fee
    bool    public dynamicFeeEnabled;
    uint256 public baseFeeBps;
    uint256 public volatilityAccum;
    uint256 public lastTradeTs;

    // Global fee growth per unit of liquidity (Q128)
    uint256 public feeGrowthGlobal0;
    uint256 public feeGrowthGlobal1;

    // Tick data
    struct TickInfo {
        int256  liquidityNet;
        uint256 liquidityGross;
        uint256 feeOutside0;
        uint256 feeOutside1;
    }
    mapping(int256 => TickInfo) public ticks;

    // Positions
    struct Position {
        uint256 liquidity;
        int256  tickLower;
        int256  tickUpper;
        uint256 feeInside0Last;
        uint256 feeInside1Last;
        uint256 owed0;
        uint256 owed1;
    }
    mapping(uint256 => Position) public positions;
    mapping(uint256 => address)  public posOwners;
    uint256 public nextPosId;

    uint256 constant Q64  = 1 << 64;
    uint256 constant Q128 = 1 << 128;
    int256  constant MIN_TICK = -500000;
    int256  constant MAX_TICK =  500000;

    event Mint(address indexed owner, uint256 indexed posId, int256 tL, int256 tU, uint256 liq, uint256 a0, uint256 a1);
    event Burn(uint256 indexed posId, uint256 liq, uint256 a0, uint256 a1);
    event Collect(uint256 indexed posId, uint256 a0, uint256 a1);
    event Swap(address indexed sender, bool zeroForOne, uint256 aIn, uint256 aOut, uint256 price, int256 tick);
    event FeeUpdated(uint256 oldBps, uint256 newBps);

    constructor(address _t0, address _t1, uint256 _feeBps, uint256 _initPrice) {
        require(_t0 != _t1, "Same token");
        factory = msg.sender;
        token0 = _t0;
        token1 = _t1;
        feeBps = _feeBps;
        baseFeeBps = _feeBps;
        dynamicFeeEnabled = true;
        sqrtPriceX64 = _initPrice;
        currentTick = _priceToTick(_initPrice);
        lastTradeTs = block.timestamp;
    }

    // ════════════════════════════════════════════════════════
    //  MINT
    // ════════════════════════════════════════════════════════
    function mint(int256 tL, int256 tU, uint256 max0, uint256 max1)
        external returns (uint256 posId, uint256 used0, uint256 used1)
    {
        require(tL < tU, "VybssPool: tickLower must be < tickUpper");
        require(tL >= MIN_TICK, "VybssPool: tickLower below MIN_TICK");
        require(tU <= MAX_TICK, "VybssPool: tickUpper above MAX_TICK");
        require(max0 > 0 || max1 > 0, "VybssPool: both amounts cannot be zero");
        
        uint256 liq = _liqForAmounts(tL, tU, max0, max1);
        require(liq > 0, "VybssPool: computed liquidity is zero - adjust amounts or range");
        (used0, used1) = _amountsForLiq(tL, tU, liq);

        if (used0 > 0) require(IERC20Pool(token0).transferFrom(msg.sender, address(this), used0), "VybssPool: token0 transferFrom failed - check balance and approval");
        if (used1 > 0) require(IERC20Pool(token1).transferFrom(msg.sender, address(this), used1), "VybssPool: token1 transferFrom failed - check balance and approval");
        reserve0 += used0;
        reserve1 += used1;

        _touchTick(tL);
        ticks[tL].liquidityGross += liq;
        ticks[tL].liquidityNet   += int256(liq);
        _touchTick(tU);
        ticks[tU].liquidityGross += liq;
        ticks[tU].liquidityNet   -= int256(liq);

        if (currentTick >= tL && currentTick < tU) liquidity += liq;

        posId = nextPosId++;
        positions[posId] = Position(liq, tL, tU,
            _feeInside0(tL, tU), _feeInside1(tL, tU), 0, 0);
        posOwners[posId] = msg.sender;
        emit Mint(msg.sender, posId, tL, tU, liq, used0, used1);
    }

    // ════════════════════════════════════════════════════════
    //  BURN
    // ════════════════════════════════════════════════════════
    function burn(uint256 posId, uint256 liqRm) external returns (uint256 a0, uint256 a1) {
        require(posOwners[posId] == msg.sender, "!owner");
        Position storage p = positions[posId];
        require(liqRm > 0 && liqRm <= p.liquidity, "liq");
        _updateFees(posId);
        (a0, a1) = _amountsForLiq(p.tickLower, p.tickUpper, liqRm);
        ticks[p.tickLower].liquidityGross -= liqRm;
        ticks[p.tickLower].liquidityNet   -= int256(liqRm);
        ticks[p.tickUpper].liquidityGross -= liqRm;
        ticks[p.tickUpper].liquidityNet   += int256(liqRm);
        if (currentTick >= p.tickLower && currentTick < p.tickUpper) liquidity -= liqRm;
        p.liquidity -= liqRm;
        p.owed0 += a0; p.owed1 += a1;
        reserve0 -= a0; reserve1 -= a1;
        emit Burn(posId, liqRm, a0, a1);
    }

    // ════════════════════════════════════════════════════════
    //  COLLECT
    // ════════════════════════════════════════════════════════
    function collect(uint256 posId) external returns (uint256 a0, uint256 a1) {
        require(posOwners[posId] == msg.sender, "!owner");
        _updateFees(posId);
        Position storage p = positions[posId];
        a0 = p.owed0; a1 = p.owed1;
        p.owed0 = 0; p.owed1 = 0;
        if (a0 > 0) require(IERC20Pool(token0).transfer(msg.sender, a0), "X0");
        if (a1 > 0) require(IERC20Pool(token1).transfer(msg.sender, a1), "X1");
        emit Collect(posId, a0, a1);
    }

    // ════════════════════════════════════════════════════════
    //  SWAP
    // ════════════════════════════════════════════════════════
    function swap(bool zeroForOne, uint256 amountIn, uint256 priceLimitX64)
        external returns (uint256 amountOut)
    {
        require(amountIn > 0, "0 in");
        if (zeroForOne) {
            require(priceLimitX64 > 0 && priceLimitX64 < sqrtPriceX64, "limit");
        } else {
            require(priceLimitX64 > sqrtPriceX64, "limit");
        }
        _refreshFee();

        uint256 rem  = amountIn;
        uint256 out  = 0;
        uint256 p    = sqrtPriceX64;
        int256  t    = currentTick;
        uint256 liq  = liquidity;

        for (uint256 i = 0; i < 300 && rem > 0; i++) {
            if (liq == 0) {
                // skip empty ticks
                t = zeroForOne ? t - 1 : t + 1;
                if (t < MIN_TICK || t > MAX_TICK) break;
                p = _tickToPrice(t);
                int256 net = ticks[t].liquidityNet;
                if (zeroForOne) {
                    if (net < 0) liq += uint256(-net); else if (uint256(net) <= liq) liq -= uint256(net); else liq = 0;
                } else {
                    if (net > 0) liq += uint256(net); else if (uint256(-net) <= liq) liq -= uint256(-net); else liq = 0;
                }
                continue;
            }

            // Compute step output using x*y=k within this tick
            uint256 stepIn;
            uint256 stepOut;
            if (zeroForOne) {
                // dx -> dy :  dy = liq * dx / (liq/p + dx)  (simplified)
                uint256 effLiq = _mul(liq, Q64) / p; // token0 equivalent
                stepIn = rem;
                stepOut = _mul(liq, stepIn) / (effLiq + stepIn);
                if (stepOut > reserve1) stepOut = reserve1;
            } else {
                uint256 effLiq = _mul(liq, p) / Q64;
                stepIn = rem;
                stepOut = _mul(liq, stepIn) / (effLiq + stepIn);
                if (stepOut > reserve0) stepOut = reserve0;
            }

            // Fee
            uint256 fee = _mul(stepIn, feeBps) / 10000;
            if (fee >= rem) fee = rem - 1;

            rem -= (stepIn > rem ? rem : stepIn);
            out += stepOut;

            // Accumulate fee growth
            if (liq > 0 && fee > 0) {
                if (zeroForOne) {
                    feeGrowthGlobal0 += _mul(fee, Q128) / liq;
                } else {
                    feeGrowthGlobal1 += _mul(fee, Q128) / liq;
                }
            }

            // Update price after swap step
            if (zeroForOne) {
                if (reserve1 > 0 && (reserve0 + stepIn) > 0) {
                    p = _sqrt(_div(_mul(_mul(reserve1, Q64), Q64), reserve0 + stepIn));
                }
            } else {
                if (reserve0 > 0 && (reserve1 + stepIn) > 0) {
                    p = _sqrt(_div(_mul(_mul(reserve0, Q64), Q64), reserve1 + stepIn));
                }
            }

            int256 newTick = _priceToTick(p);
            // Jump directly to newTick. Only cross ticks that have liquidity.
            // A full tick bitmap would be optimal, but for now we only check the
            // two position-boundary ticks that could exist between old and new.
            if (newTick != t) {
                int256 dir = newTick > t ? int256(1) : int256(-1);

                // Scan only a small neighborhood around known tick boundaries.
                // Positions create ticks at their lower & upper bounds.
                // Check each tick in the range, but only up to 50 total lookups.
                int256 cursor = t;
                for (uint256 j = 0; j < 50; j++) {
                    cursor += dir;
                    if ((dir > 0 && cursor > newTick) || (dir < 0 && cursor < newTick)) break;
                    if (ticks[cursor].liquidityGross > 0) {
                        int256 net = ticks[cursor].liquidityNet;
                        ticks[cursor].feeOutside0 = feeGrowthGlobal0 - ticks[cursor].feeOutside0;
                        ticks[cursor].feeOutside1 = feeGrowthGlobal1 - ticks[cursor].feeOutside1;
                        if (dir > 0) {
                            if (net > 0) liq += uint256(net); else if (uint256(-net) <= liq) liq -= uint256(-net); else liq = 0;
                        } else {
                            if (net < 0) liq += uint256(-net); else if (uint256(net) <= liq) liq -= uint256(net); else liq = 0;
                        }
                    }
                }
                t = newTick;
            }

            if ((zeroForOne && p <= priceLimitX64) || (!zeroForOne && p >= priceLimitX64)) break;
            rem = 0; // consumed in one step for simple pool
        }

        require(out > 0, "No output");

        sqrtPriceX64 = p;
        currentTick = t;
        liquidity = liq;

        uint256 spent = amountIn - rem;
        if (zeroForOne) {
            require(IERC20Pool(token0).transferFrom(msg.sender, address(this), spent), "XIn");
            require(IERC20Pool(token1).transfer(msg.sender, out), "XOut");
            reserve0 += spent;
            reserve1 -= out;
        } else {
            require(IERC20Pool(token1).transferFrom(msg.sender, address(this), spent), "XIn");
            require(IERC20Pool(token0).transfer(msg.sender, out), "XOut");
            reserve1 += spent;
            reserve0 -= out;
        }

        volatilityAccum = _mul(volatilityAccum, 95) / 100 + (spent > 0 ? spent : 1);
        lastTradeTs = block.timestamp;
        amountOut = out;
        emit Swap(msg.sender, zeroForOne, spent, out, p, t);
    }

    // ════════════════════════════════════════════════════════
    //  QUOTE (view)
    // ════════════════════════════════════════════════════════
    function quote(bool zeroForOne, uint256 amountIn) external view returns (uint256 amountOut) {
        if (amountIn == 0 || liquidity == 0) return 0;
        uint256 fee = _mul(amountIn, feeBps) / 10000;
        uint256 netIn = amountIn - fee;
        if (zeroForOne) {
            uint256 effLiq = _div(_mul(liquidity, Q64), sqrtPriceX64);
            amountOut = _div(_mul(liquidity, netIn), effLiq + netIn);
            if (amountOut > reserve1) amountOut = reserve1;
        } else {
            uint256 effLiq = _div(_mul(liquidity, sqrtPriceX64), Q64);
            amountOut = _div(_mul(liquidity, netIn), effLiq + netIn);
            if (amountOut > reserve0) amountOut = reserve0;
        }
    }

    // ════════════════════════════════════════════════════════
    //  VIEW HELPERS
    // ════════════════════════════════════════════════════════
    function getPoolState() external view returns (
        uint256 r0, uint256 r1, uint256 liq, uint256 price, int256 tick, uint256 fee
    ) {
        return (reserve0, reserve1, liquidity, sqrtPriceX64, currentTick, feeBps);
    }

    function getPosition(uint256 posId) external view returns (
        address owner, uint256 liq, int256 tL, int256 tU, uint256 o0, uint256 o1
    ) {
        Position memory p = positions[posId];
        return (posOwners[posId], p.liquidity, p.tickLower, p.tickUpper, p.owed0, p.owed1);
    }

    // ════════════════════════════════════════════════════════
    //  DYNAMIC FEE
    // ════════════════════════════════════════════════════════
    function _refreshFee() private {
        if (!dynamicFeeEnabled) return;
        uint256 old = feeBps;
        uint256 v = volatilityAccum;
        if (v < 1e18)      feeBps = 1;   // 0.01%
        else if (v < 1e20) feeBps = 5;   // 0.05%
        else if (v < 1e22) feeBps = 30;  // 0.30%
        else               feeBps = 100; // 1.00%
        if (feeBps != old) emit FeeUpdated(old, feeBps);
    }

    function setDynamicFee(bool on) external {
        require(msg.sender == factory, "!factory");
        dynamicFeeEnabled = on;
        if (!on) feeBps = baseFeeBps;
    }

    // ════════════════════════════════════════════════════════
    //  INTERNAL
    // ════════════════════════════════════════════════════════
    function _touchTick(int256 t) private {
        if (ticks[t].liquidityGross == 0) {
            if (currentTick >= t) {
                ticks[t].feeOutside0 = feeGrowthGlobal0;
                ticks[t].feeOutside1 = feeGrowthGlobal1;
            }
        }
    }

    function _feeInside0(int256 tL, int256 tU) private view returns (uint256) {
        uint256 below = currentTick >= tL ? ticks[tL].feeOutside0 : feeGrowthGlobal0 - ticks[tL].feeOutside0;
        uint256 above = currentTick <  tU ? ticks[tU].feeOutside0 : feeGrowthGlobal0 - ticks[tU].feeOutside0;
        return feeGrowthGlobal0 - below - above;
    }

    function _feeInside1(int256 tL, int256 tU) private view returns (uint256) {
        uint256 below = currentTick >= tL ? ticks[tL].feeOutside1 : feeGrowthGlobal1 - ticks[tL].feeOutside1;
        uint256 above = currentTick <  tU ? ticks[tU].feeOutside1 : feeGrowthGlobal1 - ticks[tU].feeOutside1;
        return feeGrowthGlobal1 - below - above;
    }

    function _updateFees(uint256 posId) private {
        Position storage p = positions[posId];
        uint256 fg0 = _feeInside0(p.tickLower, p.tickUpper);
        uint256 fg1 = _feeInside1(p.tickLower, p.tickUpper);
        if (p.liquidity > 0) {
            p.owed0 += _mul(p.liquidity, fg0 - p.feeInside0Last) / Q128;
            p.owed1 += _mul(p.liquidity, fg1 - p.feeInside1Last) / Q128;
        }
        p.feeInside0Last = fg0;
        p.feeInside1Last = fg1;
    }

    function _liqForAmounts(int256 tL, int256 tU, uint256 a0, uint256 a1) private view returns (uint256) {
        uint256 pL = _tickToPrice(tL);
        uint256 pU = _tickToPrice(tU);
        uint256 p  = sqrtPriceX64;

        if (p <= pL) {
            // all token0
            if (a0 == 0) return 0;
            return _mul(_mul(a0, pL), pU) / (_mul(pU - pL, Q64));
        } else if (p >= pU) {
            // all token1
            if (a1 == 0) return 0;
            return _mul(a1, Q64) / (pU - pL);
        } else {
            uint256 liq0 = a0 > 0 ? _mul(_mul(a0, p), pU) / (_mul(pU - p, Q64)) : type(uint256).max;
            uint256 liq1 = a1 > 0 ? _mul(a1, Q64) / (p - pL) : type(uint256).max;
            return liq0 < liq1 ? liq0 : liq1;
        }
    }

    function _amountsForLiq(int256 tL, int256 tU, uint256 liq) private view returns (uint256 a0, uint256 a1) {
        uint256 pL = _tickToPrice(tL);
        uint256 pU = _tickToPrice(tU);
        uint256 p  = sqrtPriceX64;

        if (p <= pL) {
            a0 = _mul(_mul(liq, pU - pL), Q64) / _mul(pL, pU);
        } else if (p >= pU) {
            a1 = _mul(liq, pU - pL) / Q64;
        } else {
            a0 = _mul(_mul(liq, pU - p), Q64) / _mul(p, pU);
            a1 = _mul(liq, p - pL) / Q64;
        }
    }

    function _tickToPrice(int256 t) private pure returns (uint256) {
        // sqrtPrice = 1.0001^(t/2) * Q64
        // Approximation: sqrtPrice ≈ Q64 * (1 + t * 50 / 1e6)
        if (t == 0) return Q64;
        if (t > 0) {
            return Q64 + (uint256(t) * Q64 * 50) / 1e6;
        } else {
            uint256 dec = (uint256(-t) * Q64 * 50) / 1e6;
            return dec >= Q64 ? 1 : Q64 - dec;
        }
    }

    function _priceToTick(uint256 p) private pure returns (int256) {
        if (p >= Q64) {
            return int256(((p - Q64) * 1e6) / (Q64 * 50));
        } else {
            return -int256(((Q64 - p) * 1e6) / (Q64 * 50));
        }
    }

    function _sqrt(uint256 x) private pure returns (uint256 y) {
        if (x == 0) return 0;
        y = x;
        uint256 z = (x + 1) / 2;
        while (z < y) { y = z; z = (x / z + z) / 2; }
    }

    /// @dev Workaround for Solang 0.3.3 codegen bug: uint256 multiplication
    /// only uses the low 64 bits when one operand is read from storage.
    /// Passing both operands through a pure function forces Solang to load
    /// all 4 i64 limbs (256 bits) into WASM registers.
    function _mul(uint256 a, uint256 b) private pure returns (uint256) {
        return a * b;
    }

    function _div(uint256 a, uint256 b) private pure returns (uint256) {
        return a / b;
    }
}
