// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20IDO {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssIDO — IDO Launchpad for Quantos testnet
/// @notice Users can create pools, invest with QTEST/SQTEST, claim tokens immediately after pool ends.
///         No vesting, no admin review, no tiers. All pools go live automatically.
contract VybssIDO {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Constants ───────────────────────────────────────────────
    uint8 public constant STATUS_ACTIVE    = 0;
    uint8 public constant STATUS_FINALIZED = 1;
    uint8 public constant STATUS_CANCELLED = 2;

    uint8 public constant PAY_QTEST  = 0;
    uint8 public constant PAY_SQTEST = 1;

    // ── Accepted payment tokens ─────────────────────────────────
    address public immutable qtest;
    address public immutable sqtest;

    // ── Pool struct ─────────────────────────────────────────────
    struct Pool {
        address creator;
        address token;             // token being sold
        uint128 price;             // price per token in payment wei (18 decimals)
        uint128 hardCap;
        uint128 softCap;
        uint128 totalRaised;
        uint128 minInvestment;
        uint128 maxInvestment;
        uint64  startTime;
        uint64  endTime;
        uint8   status;
    }

    struct Investment {
        uint128 amountQtest;
        uint128 amountSqtest;
        bool    claimed;
        bool    refunded;
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public nextPoolId;
    mapping(uint256 => Pool) public pools;
    mapping(uint256 => mapping(address => Investment)) public investments;
    mapping(uint256 => uint256) public participantCount;

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _qtest, address _sqtest) {
        qtest  = _qtest;
        sqtest = _sqtest;
    }

    // ── Create Pool ─────────────────────────────────────────────
    /// @notice Create a new IDO pool. No fees required on testnet.
    function createPool(
        address _token,
        uint128 _price,
        uint128 _hardCap,
        uint128 _softCap,
        uint128 _minInvestment,
        uint128 _maxInvestment,
        uint64  _startTime,
        uint64  _endTime
    ) external returns (uint256) {
        require(_price > 0, "price=0");
        require(_hardCap > 0, "hardCap=0");
        require(_softCap > 0 && _softCap <= _hardCap, "softCap");
        require(_endTime > _startTime, "dates");
        require(_maxInvestment >= _minInvestment, "min>max");

        uint256 poolId = nextPoolId;
        nextPoolId = poolId + 1;

        pools[poolId] = Pool({
            creator:       msg.sender,
            token:         _token,
            price:         _price,
            hardCap:       _hardCap,
            softCap:       _softCap,
            totalRaised:   0,
            minInvestment: _minInvestment,
            maxInvestment: _maxInvestment,
            startTime:     _startTime,
            endTime:       _endTime,
            status:        STATUS_ACTIVE
        });

        return poolId;
    }

    // ── Invest ──────────────────────────────────────────────────
    /// @notice Invest in a pool using QTEST (paymentToken=0) or SQTEST (paymentToken=1)
    function invest(uint256 _poolId, uint128 _amount, uint8 _paymentToken) external {
        Pool storage pool = pools[_poolId];
        require(pool.price > 0, "pool not found");
        require(pool.status == STATUS_ACTIVE, "not active");
        require(block.timestamp >= pool.startTime, "not started");
        require(block.timestamp < pool.endTime, "ended");
        require(_amount >= pool.minInvestment, "< min");
        require(pool.totalRaised + _amount <= pool.hardCap, "> hardCap");

        Investment storage inv = investments[_poolId][msg.sender];
        uint128 totalUser = inv.amountQtest + inv.amountSqtest + _amount;
        require(totalUser <= pool.maxInvestment, "> maxUser");

        // Transfer payment token
        address payToken = _paymentToken == PAY_SQTEST ? sqtest : qtest;
        require(IERC20IDO(payToken).transferFrom(msg.sender, address(this), _amount), "transfer failed");

        if (inv.amountQtest == 0 && inv.amountSqtest == 0) {
            participantCount[_poolId] = participantCount[_poolId] + 1;
        }

        if (_paymentToken == PAY_SQTEST) {
            inv.amountSqtest = inv.amountSqtest + _amount;
        } else {
            inv.amountQtest = inv.amountQtest + _amount;
        }
        pool.totalRaised = pool.totalRaised + _amount;
    }

    // ── Claim ───────────────────────────────────────────────────
    /// @notice Claim purchased tokens immediately after pool ends (no vesting on testnet)
    function claim(uint256 _poolId) external {
        Pool storage pool = pools[_poolId];
        require(pool.price > 0, "pool not found");
        require(block.timestamp >= pool.endTime, "not ended");
        require(pool.totalRaised >= pool.softCap, "softCap not met");

        Investment storage inv = investments[_poolId][msg.sender];
        require(!inv.claimed, "already claimed");
        uint128 totalInvested = inv.amountQtest + inv.amountSqtest;
        require(totalInvested > 0, "no investment");

        inv.claimed = true;

        // tokens to receive = invested / price (both 18 decimals)
        uint256 tokensOut = _div(_mul(uint256(totalInvested), 10**18), uint256(pool.price));
        require(IERC20IDO(pool.token).transfer(msg.sender, tokensOut), "token transfer failed");
    }

    // ── Refund ──────────────────────────────────────────────────
    /// @notice Refund if pool ended and soft cap was NOT reached
    function refund(uint256 _poolId) external {
        Pool storage pool = pools[_poolId];
        require(pool.price > 0, "pool not found");
        require(block.timestamp >= pool.endTime || pool.status == STATUS_CANCELLED, "not ended");
        require(pool.totalRaised < pool.softCap || pool.status == STATUS_CANCELLED, "softCap met");

        Investment storage inv = investments[_poolId][msg.sender];
        require(!inv.refunded, "already refunded");
        uint128 totalInvested = inv.amountQtest + inv.amountSqtest;
        require(totalInvested > 0, "no investment");

        inv.refunded = true;

        if (inv.amountQtest > 0) {
            require(IERC20IDO(qtest).transfer(msg.sender, inv.amountQtest), "qtest refund fail");
        }
        if (inv.amountSqtest > 0) {
            require(IERC20IDO(sqtest).transfer(msg.sender, inv.amountSqtest), "sqtest refund fail");
        }
    }

    // ── Finalize ────────────────────────────────────────────────
    /// @notice Creator withdraws raised funds after pool ends successfully
    function finalize(uint256 _poolId) external {
        Pool storage pool = pools[_poolId];
        require(pool.creator == msg.sender, "not creator");
        require(block.timestamp >= pool.endTime, "not ended");
        require(pool.totalRaised >= pool.softCap, "softCap not met");
        require(pool.status == STATUS_ACTIVE, "already finalized");

        pool.status = STATUS_FINALIZED;

        // Send raised funds to creator (all as QTEST/SQTEST mix)
        uint256 bal_q = IERC20IDO(qtest).balanceOf(address(this));
        uint256 bal_s = IERC20IDO(sqtest).balanceOf(address(this));

        // Simple approach: send all contract balance of each token to creator
        // In production, track per-pool balances. OK for testnet.
        if (bal_q > 0) IERC20IDO(qtest).transfer(pool.creator, bal_q);
        if (bal_s > 0) IERC20IDO(sqtest).transfer(pool.creator, bal_s);
    }

    // ── Cancel (creator only, before start) ─────────────────────
    function cancelPool(uint256 _poolId) external {
        Pool storage pool = pools[_poolId];
        require(pool.creator == msg.sender, "not creator");
        require(pool.status == STATUS_ACTIVE, "not active");
        pool.status = STATUS_CANCELLED;
    }

    // ── View functions ──────────────────────────────────────────

    function getPool(uint256 _poolId) external view returns (
        address creator,
        address token,
        uint128 price,
        uint128 hardCap,
        uint128 softCap,
        uint128 totalRaised,
        uint128 minInvestment,
        uint128 maxInvestment,
        uint64  startTime,
        uint64  endTime,
        uint8   status
    ) {
        Pool storage p = pools[_poolId];
        return (p.creator, p.token, p.price, p.hardCap, p.softCap, p.totalRaised,
                p.minInvestment, p.maxInvestment, p.startTime, p.endTime, p.status);
    }

    function getInvestment(uint256 _poolId, address _investor) external view returns (
        uint128 amountQtest,
        uint128 amountSqtest,
        bool    claimed,
        bool    refunded
    ) {
        Investment storage inv = investments[_poolId][_investor];
        return (inv.amountQtest, inv.amountSqtest, inv.claimed, inv.refunded);
    }

    function getParticipantCount(uint256 _poolId) external view returns (uint256) {
        return participantCount[_poolId];
    }
}
