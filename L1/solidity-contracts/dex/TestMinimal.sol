// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

contract TestMinimal {
    uint256 constant Q64 = 1 << 64;

    // Test 1: simple uint256 multiply
    function testMul(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }

    // Test 2: int256 negation + uint256 cast (suspected Solang bug)
    function testNeg(int256 t) external pure returns (uint256) {
        return uint256(-t);
    }

    // Test 3: _tickToPrice logic
    function testTickToPrice(int256 t) external pure returns (uint256) {
        if (t == 0) return Q64;
        if (t > 0) {
            return Q64 + (uint256(t) * Q64 * 50) / 1000000;
        } else {
            uint256 dec = (uint256(-t) * Q64 * 50) / 1000000;
            return dec >= Q64 ? 1 : Q64 - dec;
        }
    }

    // Test 4: constant Q64 value
    function testQ64() external pure returns (uint256) {
        return Q64;
    }

    // Test 5: tickToPrice without uint256(-t)
    function testTickToPrice2(int256 t) external pure returns (uint256) {
        if (t == 0) return Q64;
        if (t > 0) {
            return Q64 + (uint256(t) * Q64 * 50) / 1000000;
        } else {
            int256 absT = -t;
            uint256 uAbsT = uint256(absT);
            uint256 dec = (uAbsT * Q64 * 50) / 1000000;
            return dec >= Q64 ? 1 : Q64 - dec;
        }
    }
}
