// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  Field128
/// @notice Arithmetic in the Winterfell base field F = GF(M) where
///         M = 2^128 - 45 * 2^40 + 1 = 340282366920938463463374557953744961537.
///
/// @dev    All operations are done modulo M.  The field size fits in
///         a uint256, so every intermediate product also fits in uint256
///         (M < 2^128, so M*M < 2^256).
library Field128 {
    /// Field modulus M = 2^128 - 45 * 2^40 + 1
    uint256 internal constant M =
        340282366920938463463374557953744961537;

    /// 2^40 root of unity (used for FFT domain generation).
    uint256 internal constant G =
        23953097886125630542083529559205016746;

    /// Extension polynomial for the quadratic extension:
    /// elements are pairs (a, b) with arithmetic modulo x^2 + x + 1.
    /// The constant ALPHA is the value such that t^2 = ALPHA.
    /// For Winterfell's f128 quadratic extension, t^2 = t + 1 (i.e. ALPHA = t + 1).
    /// This is handled implicitly by the mul / square formulae below.

    // ── Base field operations ───────────────────────────────────────────

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            return c >= M ? c - M : c;
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a >= b ? a - b : M - (b - a);
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return mulmod(a, b, M);
        }
    }

    function neg(uint256 a) internal pure returns (uint256) {
        unchecked {
            return a == 0 ? 0 : M - a;
        }
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "Field128: division by zero");
        unchecked {
            return modExp(a, M - 2, M);
        }
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return mul(a, inv(b));
    }

    function pow(uint256 a, uint256 e) internal pure returns (uint256) {
        unchecked {
            return modExp(a, e, M);
        }
    }

    /// @notice Fast modular exponentiation (binary method).
    function modExp(uint256 base, uint256 exponent, uint256 modulus)
        internal
        pure
        returns (uint256 result)
    {
        assembly {
            result := 1
            let b := base
            let e := exponent
            let m := modulus
            for { } gt(e, 0) { } {
                if and(e, 1) { result := mulmod(result, b, m) }
                b := mulmod(b, b, m)
                e := shr(1, e)
            }
        }
    }

    // ── Quadratic extension operations ────────────────────────────────────

    struct Quad {
        uint256 a; // real part
        uint256 b; // imaginary part
    }

    function quadZero() internal pure returns (Quad memory) {
        return Quad(0, 0);
    }

    function quadOne() internal pure returns (Quad memory) {
        return Quad(1, 0);
    }

    function quadAdd(Quad memory x, Quad memory y)
        internal
        pure
        returns (Quad memory)
    {
        return Quad(add(x.a, y.a), add(x.b, y.b));
    }

    function quadSub(Quad memory x, Quad memory y)
        internal
        pure
        returns (Quad memory)
    {
        return Quad(sub(x.a, y.a), sub(x.b, y.b));
    }

    /// Multiply two quadratic extension elements.
    /// Uses the exact formula from Winterfell f128 quadratic extension:
    ///   r0 = a0*b0 + a1*b1
    ///   r1 = (a0 + a1)*(b0 + b1) - a0*b0
    function quadMul(Quad memory x, Quad memory y)
        internal
        pure
        returns (Quad memory)
    {
        uint256 z = mul(x.a, y.a);
        return Quad(
            add(z, mul(x.b, y.b)),           // a0*b0 + a1*b1
            sub(mul(add(x.a, x.b), add(y.a, y.b)), z) // (a0+a1)*(b0+b1) - a0*b0
        );
    }

    function quadSquare(Quad memory x)
        internal
        pure
        returns (Quad memory)
    {
        uint256 t0 = mul(x.a, x.a);
        uint256 t1 = mul(x.b, x.b);
        uint256 t2 = mul(add(x.a, x.b), add(x.a, x.b));
        return Quad(add(t0, t1), sub(t2, t0));
    }

    function quadMulBase(Quad memory x, uint256 b)
        internal
        pure
        returns (Quad memory)
    {
        return Quad(mul(x.a, b), mul(x.b, b));
    }

    function quadInv(Quad memory x) internal pure returns (Quad memory) {
        // For extension x^2 = 1:
        // 1/(a + bt) = (a - bt)/(a^2 - b^2)
        uint256 denom = sub(mul(x.a, x.a), mul(x.b, x.b));
        uint256 invDenom = inv(denom);
        return Quad(mul(x.a, invDenom), mul(neg(x.b), invDenom));
    }

    // ── Domain generation ────────────────────────────────────────────────

    /// Compute g^i mod M for domain point i.
    function getDomainPoint(uint64 i, uint64 domainSize)
        internal
        pure
        returns (uint256)
    {
        uint256 exp = (M - 1) / domainSize;
        return pow(G, exp * i);
    }
}
