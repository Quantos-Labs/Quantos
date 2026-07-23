// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20P2P {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssP2PEscrow — P2P Trading Escrow for Quantos testnet
/// @notice Sellers lock tokens into escrow. Buyer sends the quote token to complete the trade.
///         Seller releases tokens to buyer, or funds are refunded after timeout.
contract VybssP2PEscrow {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Escrow status constants ─────────────────────────────────
    uint8 public constant STATUS_LOCKED    = 0;
    uint8 public constant STATUS_RELEASED  = 1;
    uint8 public constant STATUS_REFUNDED  = 2;
    uint8 public constant STATUS_DISPUTED  = 3;

    uint8 public constant PAY_QTEST  = 0;
    uint8 public constant PAY_SQTEST = 1;

    // ── Accepted payment tokens ─────────────────────────────────
    address public immutable qtest;
    address public immutable sqtest;

    // ── Escrow struct ───────────────────────────────────────────
    struct Escrow {
        address seller;
        address buyer;
        uint128 amount;
        uint8   paymentToken;      // 0=QTEST, 1=SQTEST
        uint8   status;
        uint64  createdAt;
        uint64  timeoutAt;
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public nextEscrowId;
    mapping(uint256 => Escrow) public escrows;

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _qtest, address _sqtest) {
        qtest  = _qtest;
        sqtest = _sqtest;
    }

    // ── Create Escrow (seller locks tokens) ─────────────────────
    /// @notice Seller creates an escrow by locking tokens. Buyer address can be set later.
    /// @param _buyer The buyer address (or address(0) if not yet known)
    /// @param _amount Amount of tokens to lock
    /// @param _paymentToken 0=QTEST, 1=SQTEST
    /// @param _timeout Duration in seconds before auto-refund is possible
    function createEscrow(
        address _buyer,
        uint128 _amount,
        uint8   _paymentToken,
        uint64  _timeout
    ) external returns (uint256) {
        require(_amount > 0, "amount=0");
        require(_timeout >= 900, "timeout<15min");  // Minimum 15 minutes

        address payToken = _paymentToken == PAY_SQTEST ? sqtest : qtest;
        require(IERC20P2P(payToken).transferFrom(msg.sender, address(this), _amount), "transfer failed");

        uint256 escrowId = nextEscrowId;
        nextEscrowId = escrowId + 1;

        escrows[escrowId] = Escrow({
            seller:       msg.sender,
            buyer:        _buyer,
            amount:       _amount,
            paymentToken: _paymentToken,
            status:       STATUS_LOCKED,
            createdAt:    uint64(block.timestamp),
            timeoutAt:    uint64(block.timestamp) + _timeout
        });

        return escrowId;
    }

    // ── Set Buyer (if not set at creation) ──────────────────────
    /// @notice Seller sets the buyer address after a trade is initiated
    function setBuyer(uint256 _escrowId, address _buyer) external {
        Escrow storage esc = escrows[_escrowId];
        require(esc.seller == msg.sender, "not seller");
        require(esc.status == STATUS_LOCKED, "not locked");
        require(esc.buyer == address(0), "buyer already set");
        require(_buyer != address(0), "invalid buyer");
        esc.buyer = _buyer;
    }

    // ── Release Escrow (seller confirms payment received) ───────
    /// @notice Seller releases escrowed tokens to buyer after confirming quote token received
    function releaseEscrow(uint256 _escrowId) external {
        Escrow storage esc = escrows[_escrowId];
        require(esc.seller == msg.sender, "not seller");
        require(esc.status == STATUS_LOCKED, "not locked");
        require(esc.buyer != address(0), "no buyer");

        esc.status = STATUS_RELEASED;

        address payToken = esc.paymentToken == PAY_SQTEST ? sqtest : qtest;
        require(IERC20P2P(payToken).transfer(esc.buyer, esc.amount), "release failed");
    }

    // ── Refund Escrow (after timeout) ───────────────────────────
    /// @notice Seller can reclaim tokens after the timeout has passed
    function refundEscrow(uint256 _escrowId) external {
        Escrow storage esc = escrows[_escrowId];
        require(esc.seller == msg.sender, "not seller");
        require(esc.status == STATUS_LOCKED, "not locked");
        require(block.timestamp >= esc.timeoutAt, "not timed out");

        esc.status = STATUS_REFUNDED;

        address payToken = esc.paymentToken == PAY_SQTEST ? sqtest : qtest;
        require(IERC20P2P(payToken).transfer(esc.seller, esc.amount), "refund failed");
    }

    // ── Dispute Escrow ──────────────────────────────────────────
    /// @notice Either party can mark the escrow as disputed
    function disputeEscrow(uint256 _escrowId) external {
        Escrow storage esc = escrows[_escrowId];
        require(esc.status == STATUS_LOCKED, "not locked");
        require(msg.sender == esc.seller || msg.sender == esc.buyer, "not party");

        esc.status = STATUS_DISPUTED;
    }

    // ── View functions ──────────────────────────────────────────

    function getEscrow(uint256 _escrowId) external view returns (
        address seller,
        address buyer,
        uint128 amount,
        uint8   paymentToken,
        uint8   status,
        uint64  createdAt,
        uint64  timeoutAt
    ) {
        Escrow storage esc = escrows[_escrowId];
        return (
            esc.seller,
            esc.buyer,
            esc.amount,
            esc.paymentToken,
            esc.status,
            esc.createdAt,
            esc.timeoutAt
        );
    }
}
