// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestMath {
    uint256 public storedValue;
    uint256 constant Q64 = 1 << 64;

    constructor(uint256 _val) {
        storedValue = _val;
    }

    // Test 1: just read storage and return
    function readOnly() external view returns (uint256) {
        return storedValue;
    }

    // Test 2: pure math with int256 negation
    function tickToPrice(int256 t) external pure returns (uint256) {
        if (t == 0) return Q64;
        if (t > 0) {
            return Q64 + (uint256(t) * Q64 * 50) / 1e6;
        } else {
            uint256 dec = (uint256(-t) * Q64 * 50) / 1e6;
            return dec >= Q64 ? 1 : Q64 - dec;
        }
    }

    // Test 3: multiply large numbers  
    function mulTest(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a * b * c;
    }

    // Test 4: full liqForAmounts computation
    function liqForAmounts(int256 tL, int256 tU, uint256 a0, uint256 a1) external view returns (uint256) {
        uint256 pL = _tickToPrice(tL);
        uint256 pU = _tickToPrice(tU);
        uint256 p  = storedValue;

        if (p <= pL) {
            if (a0 == 0) return 0;
            return (a0 * pL * pU) / ((pU - pL) * Q64);
        } else if (p >= pU) {
            if (a1 == 0) return 0;
            return (a1 * Q64) / (pU - pL);
        } else {
            uint256 liq0 = a0 > 0 ? (a0 * p * pU) / ((pU - p) * Q64) : type(uint256).max;
            uint256 liq1 = a1 > 0 ? (a1 * Q64) / (p - pL) : type(uint256).max;
            return liq0 < liq1 ? liq0 : liq1;
        }
    }

    // Test 5: step-by-step liqForAmounts — return intermediate values
    function liqStep1(int256 tL, int256 tU) external view returns (uint256 pL, uint256 pU, uint256 p) {
        pL = _tickToPrice(tL);
        pU = _tickToPrice(tU);
        p  = storedValue;
    }

    // Test 6: just the denominator computation
    function denomTest(uint256 pU, uint256 p) external pure returns (uint256) {
        return (pU - p) * Q64;
    }

    // Test 7: the full division
    function divTest(uint256 a0, uint256 p, uint256 pU) external pure returns (uint256) {
        uint256 num = a0 * p * pU;
        uint256 den = (pU - p) * Q64;
        return num / den;
    }

    // Test 8: ternary with division — exactly as in liqForAmounts
    function ternaryTest(uint256 a0, uint256 p, uint256 pU, uint256 pL) external pure returns (uint256) {
        uint256 liq0 = a0 > 0 ? (a0 * p * pU) / ((pU - p) * Q64) : type(uint256).max;
        uint256 liq1 = a0 > 0 ? (a0 * Q64) / (p - pL) : type(uint256).max;
        return liq0 < liq1 ? liq0 : liq1;
    }

    // Test 9: liqForAmounts but without ternary
    function liqNoTernary(int256 tL, int256 tU, uint256 a0, uint256 a1) external view returns (uint256) {
        uint256 pL = _tickToPrice(tL);
        uint256 pU = _tickToPrice(tU);
        uint256 p  = storedValue;
        // Skip comparisons, assume p is between pL and pU
        uint256 num0 = a0 * p * pU;
        uint256 den0 = (pU - p) * Q64;
        uint256 liq0 = num0 / den0;
        uint256 num1 = a1 * Q64;
        uint256 den1 = p - pL;
        uint256 liq1 = num1 / den1;
        return liq0 < liq1 ? liq0 : liq1;
    }

    // Test 10: same math but all pure (no storage read)
    function liqPure(int256 tL, int256 tU, uint256 a0, uint256 a1, uint256 pVal) external pure returns (uint256) {
        uint256 pL = _tickToPrice(tL);
        uint256 pU = _tickToPrice(tU);
        uint256 p  = pVal;
        uint256 num0 = a0 * p * pU;
        uint256 den0 = (pU - p) * Q64;
        uint256 liq0 = num0 / den0;
        uint256 num1 = a1 * Q64;
        uint256 den1 = p - pL;
        uint256 liq1 = num1 / den1;
        return liq0 < liq1 ? liq0 : liq1;
    }

    // Test 11: simple storage read + multiply (no _tickToPrice)
    function storeMulTest(uint256 a, uint256 b) external view returns (uint256) {
        uint256 p = storedValue;
        return a * p * b;
    }

    // Test 12: storage read + identity
    function storeIdentity() external view returns (uint256) {
        uint256 p = storedValue;
        return p;
    }

    // Test 13: storage read + add 1
    function storeAddOne() external view returns (uint256) {
        uint256 p = storedValue;
        return p + 1;
    }

    // Test 14: storage read + multiply by 2
    function storeMul2() external view returns (uint256) {
        uint256 p = storedValue;
        return p * 2;
    }

    // Test 15: storage read + small multiply
    function storeSmallMul(uint256 a) external view returns (uint256) {
        uint256 p = storedValue;
        return p * a;
    }

    // Test 16: workaround — pass storage value through pure function param
    function storeMul2ViaParam() external view returns (uint256) {
        return _mulByTwo(storedValue);
    }

    function _mulByTwo(uint256 v) private pure returns (uint256) {
        return v * 2;
    }

    // Test 17: workaround — storage mul via generic pure helper
    function storeMulViaHelper(uint256 a) external view returns (uint256) {
        return _safeMul(storedValue, a);
    }

    function _safeMul(uint256 x, uint256 y) private pure returns (uint256) {
        return x * y;
    }

    function _tickToPrice(int256 t) private pure returns (uint256) {
        if (t == 0) return Q64;
        if (t > 0) {
            return Q64 + (uint256(t) * Q64 * 50) / 1e6;
        } else {
            uint256 dec = (uint256(-t) * Q64 * 50) / 1e6;
            return dec >= Q64 ? 1 : Q64 - dec;
        }
    }
}
