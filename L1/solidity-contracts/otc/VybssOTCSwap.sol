// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20OTC {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssOTCSwap — Trustless atomic OTC swaps on Quantos
/// @notice Two parties deposit their tokens into the contract, then after both
///         deposits are confirmed the contract swaps them atomically.
///         If one side doesn't deposit before the timeout, the other side can refund.
contract VybssOTCSwap {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Deal status constants ───────────────────────────────────
    uint8 public constant STATUS_OPEN      = 0;  // Waiting for both deposits
    uint8 public constant STATUS_SETTLED   = 1;  // Swapped successfully
    uint8 public constant STATUS_CANCELLED = 2;  // Cancelled before both deposit
    uint8 public constant STATUS_REFUNDED  = 3;  // Refunded after timeout

    uint8 public constant TOKEN_QTEST  = 0;
    uint8 public constant TOKEN_SQTEST = 1;

    // ── Token addresses ─────────────────────────────────────────
    address public immutable qtest;
    address public immutable sqtest;

    // ── Deal struct ─────────────────────────────────────────────
    struct Deal {
        address maker;             // Creator of the deal
        address taker;             // Counterparty
        uint8   makerToken;        // 0=QTEST, 1=SQTEST — token maker gives
        uint128 makerAmount;       // Amount maker deposits
        uint8   takerToken;        // 0=QTEST, 1=SQTEST — token taker gives
        uint128 takerAmount;       // Amount taker deposits
        bool    makerDeposited;
        bool    takerDeposited;
        uint8   status;
        uint64  createdAt;
        uint64  timeoutAt;
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public nextDealId;
    mapping(uint256 => Deal) public deals;

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _qtest, address _sqtest) {
        qtest  = _qtest;
        sqtest = _sqtest;
    }

    // ── Helpers ─────────────────────────────────────────────────
    function _tokenAddress(uint8 tokenId) internal view returns (address) {
        if (tokenId == TOKEN_SQTEST) return sqtest;
        return qtest;
    }

    // ── Create Deal ─────────────────────────────────────────────
    /// @notice Maker creates a deal specifying what they give and what they want
    /// @param _taker           Counterparty address
    /// @param _makerToken      0=QTEST, 1=SQTEST — what maker gives
    /// @param _makerAmount     How much maker will deposit
    /// @param _takerToken      0=QTEST, 1=SQTEST — what taker gives
    /// @param _takerAmount     How much taker must deposit
    /// @param _timeoutSeconds  Seconds until refund is available
    function createDeal(
        address _taker,
        uint8   _makerToken,
        uint128 _makerAmount,
        uint8   _takerToken,
        uint128 _takerAmount,
        uint64  _timeoutSeconds
    ) external returns (uint256) {
        require(_makerAmount > 0 && _takerAmount > 0, "amounts must be > 0");
        require(_makerToken != _takerToken, "tokens must differ");
        require(_timeoutSeconds >= 900, "timeout min 15min");
        require(_taker != address(0), "invalid taker");
        require(_taker != msg.sender, "cannot self-deal");

        uint256 dealId = nextDealId;
        nextDealId = dealId + 1;

        deals[dealId] = Deal({
            maker:           msg.sender,
            taker:           _taker,
            makerToken:      _makerToken,
            makerAmount:     _makerAmount,
            takerToken:      _takerToken,
            takerAmount:     _takerAmount,
            makerDeposited:  false,
            takerDeposited:  false,
            status:          STATUS_OPEN,
            createdAt:       uint64(block.timestamp),
            timeoutAt:       uint64(block.timestamp) + _timeoutSeconds
        });

        return dealId;
    }

    // ── Deposit ─────────────────────────────────────────────────
    /// @notice Each party calls this to deposit their tokens
    function deposit(uint256 _dealId) external {
        Deal storage d = deals[_dealId];
        require(d.status == STATUS_OPEN, "deal not open");
        require(block.timestamp < d.timeoutAt, "deal timed out");

        if (msg.sender == d.maker) {
            require(!d.makerDeposited, "already deposited");
            address token = _tokenAddress(d.makerToken);
            require(IERC20OTC(token).transferFrom(msg.sender, address(this), d.makerAmount), "maker transfer failed");
            d.makerDeposited = true;
        } else if (msg.sender == d.taker) {
            require(!d.takerDeposited, "already deposited");
            address token = _tokenAddress(d.takerToken);
            require(IERC20OTC(token).transferFrom(msg.sender, address(this), d.takerAmount), "taker transfer failed");
            d.takerDeposited = true;
        } else {
            revert("not a party to this deal");
        }

        // If both deposited, auto-settle
        if (d.makerDeposited && d.takerDeposited) {
            _settle(_dealId);
        }
    }

    // ── Internal Settle ─────────────────────────────────────────
    function _settle(uint256 _dealId) internal {
        Deal storage d = deals[_dealId];
        d.status = STATUS_SETTLED;

        // Swap: maker's tokens → taker, taker's tokens → maker
        address makerTokenAddr = _tokenAddress(d.makerToken);
        address takerTokenAddr = _tokenAddress(d.takerToken);

        require(IERC20OTC(makerTokenAddr).transfer(d.taker, d.makerAmount), "settle maker→taker failed");
        require(IERC20OTC(takerTokenAddr).transfer(d.maker, d.takerAmount), "settle taker→maker failed");
    }

    // ── Cancel ──────────────────────────────────────────────────
    /// @notice Maker can cancel before taker deposits (refunds maker if deposited)
    function cancel(uint256 _dealId) external {
        Deal storage d = deals[_dealId];
        require(d.status == STATUS_OPEN, "deal not open");
        require(msg.sender == d.maker, "only maker can cancel");
        require(!d.takerDeposited, "taker already deposited");

        d.status = STATUS_CANCELLED;

        // Refund maker if they deposited
        if (d.makerDeposited) {
            address token = _tokenAddress(d.makerToken);
            require(IERC20OTC(token).transfer(d.maker, d.makerAmount), "refund maker failed");
            d.makerDeposited = false;
        }
    }

    // ── Refund after timeout ────────────────────────────────────
    /// @notice Either party can reclaim their tokens after timeout if deal isn't settled
    function refund(uint256 _dealId) external {
        Deal storage d = deals[_dealId];
        require(d.status == STATUS_OPEN, "deal not open");
        require(block.timestamp >= d.timeoutAt, "not timed out yet");

        d.status = STATUS_REFUNDED;

        // Refund anyone who deposited
        if (d.makerDeposited) {
            address makerTokenAddr = _tokenAddress(d.makerToken);
            require(IERC20OTC(makerTokenAddr).transfer(d.maker, d.makerAmount), "refund maker failed");
        }
        if (d.takerDeposited) {
            address takerTokenAddr = _tokenAddress(d.takerToken);
            require(IERC20OTC(takerTokenAddr).transfer(d.taker, d.takerAmount), "refund taker failed");
        }
    }

    // ── View: Get Deal ──────────────────────────────────────────
    function getDeal(uint256 _dealId) external view returns (
        address maker,
        address taker,
        uint8   makerToken,
        uint128 makerAmount,
        uint8   takerToken,
        uint128 takerAmount,
        bool    makerDeposited,
        bool    takerDeposited,
        uint8   status,
        uint64  createdAt,
        uint64  timeoutAt
    ) {
        Deal storage d = deals[_dealId];
        return (d.maker, d.taker, d.makerToken, d.makerAmount, d.takerToken, d.takerAmount,
                d.makerDeposited, d.takerDeposited, d.status, d.createdAt, d.timeoutAt);
    }
}
