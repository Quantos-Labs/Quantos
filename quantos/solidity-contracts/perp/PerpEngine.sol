// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPriceOracle {
    function getNormalizedPrice(bytes32 feedId) external view returns (uint256);
    function isPriceFresh(bytes32 feedId, uint64 maxAge) external view returns (bool);
}

/// @title PerpEngine - Perpetual futures engine for Quantos derivatives
/// @notice Handles margin, orders, positions, funding, and liquidations
/// @dev Settlement in QTEST. Prices from PriceOracle (Pyth-fed).
contract PerpEngine {
    address public owner;
    IERC20  public qtest;
    IPriceOracle public oracle;

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    uint256 public constant PRECISION  = 1e18;
    uint256 public constant BPS_BASE   = 10000;
    uint64  public constant MAX_STALE  = 60;  // max 60s stale price

    // ── Market configuration ────────────────────────────────────
    struct Market {
        bytes32 feedId;          // Pyth price feed ID
        bool    active;
        uint256 maxLeverage;     // e.g. 100 = 100x
        uint256 makerFeeBps;     // e.g. 2 = 0.02%
        uint256 takerFeeBps;     // e.g. 5 = 0.05%
        uint256 minOrderSize;    // min notional in QTEST (18 dec)
        uint256 maintenanceMarginBps; // e.g. 50 = 0.5%
        uint256 openInterestLong;
        uint256 openInterestShort;
        int256  fundingRate;     // scaled 1e18, positive = longs pay shorts
        uint256 lastFundingTime;
    }

    // ── Position ────────────────────────────────────────────────
    struct Position {
        bool    exists;
        bool    isLong;
        uint256 size;            // base asset size (18 dec)
        uint256 entryPrice;      // (18 dec)
        uint256 margin;          // collateral in QTEST (18 dec)
        uint256 leverage;
        int256  cumulativeFunding; // funding accrued at entry
        uint256 lastUpdateTime;
    }

    // ── Order ───────────────────────────────────────────────────
    enum OrderType { Market, Limit, Stop, StopLimit, TrailingStop }
    enum OrderStatus { Open, Filled, Cancelled }

    struct Order {
        bool       exists;
        address    trader;
        uint256    marketId;
        bool       isLong;
        OrderType  orderType;
        OrderStatus status;
        uint256    size;         // base asset
        uint256    price;        // limit/stop price (18 dec)
        uint256    triggerPrice; // for stop orders
        uint256    leverage;
        uint256    margin;
        bool       reduceOnly;
        bool       postOnly;
        uint256    createdAt;
    }

    // ── Account ─────────────────────────────────────────────────
    struct Account {
        uint256 balance;         // free margin in QTEST
        uint256 lockedMargin;    // margin in positions
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public marketCount;
    mapping(uint256 => Market)   public markets;

    uint256 public nextOrderId;
    mapping(uint256 => Order)    public orders;

    // trader => marketId => Position
    mapping(address => mapping(uint256 => Position)) public positions;

    // trader => Account
    mapping(address => Account)  public accounts;

    // Insurance fund
    uint256 public insuranceFund;

    // ── Events ──────────────────────────────────────────────────
    event MarketAdded(uint256 indexed marketId, bytes32 feedId, uint256 maxLeverage);
    event MarketPaused(uint256 indexed marketId);
    event MarketResumed(uint256 indexed marketId);
    event Deposit(address indexed trader, uint256 amount);
    event Withdrawal(address indexed trader, uint256 amount);
    event OrderPlaced(uint256 indexed orderId, address indexed trader, uint256 marketId, bool isLong, uint256 size, uint256 price);
    event OrderCancelled(uint256 indexed orderId);
    event OrderFilled(uint256 indexed orderId, uint256 fillPrice, uint256 fee);
    event PositionOpened(address indexed trader, uint256 marketId, bool isLong, uint256 size, uint256 entryPrice, uint256 leverage);
    event PositionClosed(address indexed trader, uint256 marketId, int256 pnl, uint256 exitPrice);
    event PositionLiquidated(address indexed trader, uint256 marketId, address liquidator, int256 pnl);
    event FundingPaid(uint256 indexed marketId, int256 fundingRate);

    constructor(address _qtest, address _oracle) {
        require(_qtest != address(0) && _oracle != address(0), "Invalid addresses");
        owner = msg.sender;
        qtest = IERC20(_qtest);
        oracle = IPriceOracle(_oracle);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // ══════════════════════════════════════════════════════════
    // ── ADMIN ───────────────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid");
        owner = newOwner;
    }

    function setOracle(address _oracle) external onlyOwner {
        require(_oracle != address(0), "Invalid");
        oracle = IPriceOracle(_oracle);
    }

    function addMarket(
        bytes32 feedId,
        uint256 maxLeverage,
        uint256 makerFeeBps,
        uint256 takerFeeBps,
        uint256 minOrderSize,
        uint256 maintenanceMarginBps
    ) external onlyOwner returns (uint256) {
        uint256 id = marketCount;
        markets[id] = Market({
            feedId:               feedId,
            active:               true,
            maxLeverage:          maxLeverage,
            makerFeeBps:          makerFeeBps,
            takerFeeBps:          takerFeeBps,
            minOrderSize:         minOrderSize,
            maintenanceMarginBps: maintenanceMarginBps,
            openInterestLong:     0,
            openInterestShort:    0,
            fundingRate:          0,
            lastFundingTime:      block.timestamp
        });
        marketCount = id + 1;
        emit MarketAdded(id, feedId, maxLeverage);
        return id;
    }

    function pauseMarket(uint256 marketId) external onlyOwner {
        require(marketId < marketCount, "Invalid market");
        markets[marketId].active = false;
        emit MarketPaused(marketId);
    }

    function resumeMarket(uint256 marketId) external onlyOwner {
        require(marketId < marketCount, "Invalid market");
        markets[marketId].active = true;
        emit MarketResumed(marketId);
    }

    // ══════════════════════════════════════════════════════════
    // ── MARGIN MANAGEMENT ───────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Deposit QTEST margin into trading account
    function depositMargin(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(qtest.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        accounts[msg.sender].balance += amount;
        emit Deposit(msg.sender, amount);
    }

    /// @notice Withdraw free margin
    function withdrawMargin(uint256 amount) external {
        require(amount > 0, "Zero amount");
        Account storage acc = accounts[msg.sender];
        require(acc.balance >= amount, "Insufficient balance");
        acc.balance -= amount;
        require(qtest.transfer(msg.sender, amount), "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    // ══════════════════════════════════════════════════════════
    // ── ORDER MANAGEMENT ────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Place a new order
    function placeOrder(
        uint256   marketId,
        bool      isLong,
        OrderType orderType,
        uint256   size,
        uint256   price,
        uint256   leverage,
        bool      reduceOnly,
        bool      postOnly
    ) external returns (uint256) {
        Market storage mkt = markets[marketId];
        require(mkt.active, "Market not active");
        require(leverage > 0 && leverage <= mkt.maxLeverage, "Invalid leverage");

        // Calculate required margin = notional / leverage
        uint256 markPrice = _getMarkPrice(marketId);
        uint256 notional = _mul(size, markPrice) / PRECISION;
        require(notional >= mkt.minOrderSize, "Below min order size");

        uint256 requiredMargin = _div(notional, leverage);

        if (!reduceOnly) {
            Account storage acc = accounts[msg.sender];
            require(acc.balance >= requiredMargin, "Insufficient margin");
            acc.balance -= requiredMargin;
            acc.lockedMargin += requiredMargin;
        }

        uint256 orderId = nextOrderId;
        orders[orderId] = Order({
            exists:       true,
            trader:       msg.sender,
            marketId:     marketId,
            isLong:       isLong,
            orderType:    orderType,
            status:       OrderStatus.Open,
            size:         size,
            price:        price,
            triggerPrice: price,   // for stop orders
            leverage:     leverage,
            margin:       requiredMargin,
            reduceOnly:   reduceOnly,
            postOnly:     postOnly,
            createdAt:    block.timestamp
        });
        nextOrderId = orderId + 1;

        emit OrderPlaced(orderId, msg.sender, marketId, isLong, size, price);

        // Auto-fill market orders immediately
        if (orderType == OrderType.Market) {
            _fillOrder(orderId, markPrice);
        }

        return orderId;
    }

    /// @notice Cancel an open order
    function cancelOrder(uint256 orderId) external {
        Order storage o = orders[orderId];
        require(o.exists && o.trader == msg.sender, "Not your order");
        require(o.status == OrderStatus.Open, "Not open");

        o.status = OrderStatus.Cancelled;

        // Refund locked margin
        if (!o.reduceOnly && o.margin > 0) {
            accounts[msg.sender].lockedMargin -= o.margin;
            accounts[msg.sender].balance += o.margin;
        }

        emit OrderCancelled(orderId);
    }

    // ── Internal order fill ─────────────────────────────────────

    function _fillOrder(uint256 orderId, uint256 fillPrice) internal {
        Order storage o = orders[orderId];
        require(o.status == OrderStatus.Open, "Not open");

        o.status = OrderStatus.Filled;
        Market storage mkt = markets[o.marketId];

        // Calculate fee
        uint256 notional = _mul(o.size, fillPrice) / PRECISION;
        uint256 fee = _div(_mul(notional, mkt.takerFeeBps), BPS_BASE);

        // Deduct fee from margin
        uint256 effectiveMargin = o.margin > fee ? o.margin - fee : 0;
        insuranceFund += fee;

        Position storage pos = positions[o.trader][o.marketId];

        if (pos.exists && pos.isLong != o.isLong) {
            // Closing or reducing opposite position
            _closePosition(o.trader, o.marketId, fillPrice, o.size);
        } else if (pos.exists && pos.isLong == o.isLong) {
            // Adding to existing position — weighted average entry
            uint256 oldNotional = _mul(pos.size, pos.entryPrice) / PRECISION;
            uint256 newNotional = _mul(o.size, fillPrice) / PRECISION;
            uint256 totalSize = pos.size + o.size;
            pos.entryPrice = _div(_mul(oldNotional + newNotional, PRECISION), totalSize);
            pos.size = totalSize;
            pos.margin += effectiveMargin;

            if (o.isLong) {
                mkt.openInterestLong += o.size;
            } else {
                mkt.openInterestShort += o.size;
            }
        } else {
            // New position
            positions[o.trader][o.marketId] = Position({
                exists:            true,
                isLong:            o.isLong,
                size:              o.size,
                entryPrice:        fillPrice,
                margin:            effectiveMargin,
                leverage:          o.leverage,
                cumulativeFunding: mkt.fundingRate,
                lastUpdateTime:    block.timestamp
            });

            if (o.isLong) {
                mkt.openInterestLong += o.size;
            } else {
                mkt.openInterestShort += o.size;
            }

            emit PositionOpened(o.trader, o.marketId, o.isLong, o.size, fillPrice, o.leverage);
        }

        emit OrderFilled(orderId, fillPrice, fee);
    }

    // ══════════════════════════════════════════════════════════
    // ── POSITION MANAGEMENT ─────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Close an entire position at market price
    function closePosition(uint256 marketId) external {
        Position storage pos = positions[msg.sender][marketId];
        require(pos.exists && pos.size > 0, "No position");

        uint256 markPrice = _getMarkPrice(marketId);
        _closePosition(msg.sender, marketId, markPrice, pos.size);
    }

    function _closePosition(address trader, uint256 marketId, uint256 exitPrice, uint256 closeSize) internal {
        Position storage pos = positions[trader][marketId];
        require(pos.exists, "No position");

        uint256 actualClose = closeSize > pos.size ? pos.size : closeSize;
        Market storage mkt = markets[marketId];

        // Calculate PnL
        int256 pnl = _calculatePnl(pos.isLong, pos.entryPrice, exitPrice, actualClose);

        // Calculate funding payment
        int256 fundingDelta = mkt.fundingRate - pos.cumulativeFunding;
        int256 fundingPayment = (fundingDelta * int256(actualClose)) / int256(PRECISION);
        if (pos.isLong) fundingPayment = -fundingPayment; // longs pay when rate > 0
        pnl += fundingPayment;

        // Calculate closing fee
        uint256 closeNotional = _mul(actualClose, exitPrice) / PRECISION;
        uint256 closeFee = _div(_mul(closeNotional, mkt.takerFeeBps), BPS_BASE);
        pnl -= int256(closeFee);
        insuranceFund += closeFee;

        // Proportional margin release
        uint256 marginRelease = _div(_mul(pos.margin, actualClose), pos.size);

        // Update OI
        if (pos.isLong) {
            mkt.openInterestLong = mkt.openInterestLong > actualClose
                ? mkt.openInterestLong - actualClose : 0;
        } else {
            mkt.openInterestShort = mkt.openInterestShort > actualClose
                ? mkt.openInterestShort - actualClose : 0;
        }

        if (actualClose >= pos.size) {
            // Full close
            delete positions[trader][marketId];
        } else {
            pos.size -= actualClose;
            pos.margin -= marginRelease;
            pos.cumulativeFunding = mkt.fundingRate;
            pos.lastUpdateTime = block.timestamp;
        }

        // Settle PnL to account
        Account storage acc = accounts[trader];
        acc.lockedMargin = acc.lockedMargin > marginRelease
            ? acc.lockedMargin - marginRelease : 0;

        int256 settlement = int256(marginRelease) + pnl;
        if (settlement > 0) {
            acc.balance += uint256(settlement);
        } else {
            // Loss exceeds margin => insurance fund covers
            uint256 loss = uint256(-settlement);
            if (loss <= acc.balance) {
                acc.balance -= loss;
            } else {
                insuranceFund = insuranceFund > loss ? insuranceFund - loss : 0;
                acc.balance = 0;
            }
        }

        emit PositionClosed(trader, marketId, pnl, exitPrice);
    }

    // ══════════════════════════════════════════════════════════
    // ── LIQUIDATIONS ────────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Liquidate an undercollateralized position
    function liquidate(address trader, uint256 marketId) external {
        Position storage pos = positions[trader][marketId];
        require(pos.exists && pos.size > 0, "No position");

        uint256 markPrice = _getMarkPrice(marketId);
        require(_isLiquidatable(trader, marketId, markPrice), "Not liquidatable");

        Market storage mkt = markets[marketId];

        // Calculate PnL at liquidation
        int256 pnl = _calculatePnl(pos.isLong, pos.entryPrice, markPrice, pos.size);
        uint256 margin = pos.margin;

        // Liquidation penalty (half to liquidator, half to insurance)
        uint256 penalty = _div(_mul(margin, 500), BPS_BASE); // 5% penalty
        uint256 liquidatorReward = penalty / 2;
        uint256 insurancePortion = penalty - liquidatorReward;

        // Update OI
        if (pos.isLong) {
            mkt.openInterestLong = mkt.openInterestLong > pos.size
                ? mkt.openInterestLong - pos.size : 0;
        } else {
            mkt.openInterestShort = mkt.openInterestShort > pos.size
                ? mkt.openInterestShort - pos.size : 0;
        }

        // Clear position
        delete positions[trader][marketId];

        // Settle
        Account storage traderAcc = accounts[trader];
        traderAcc.lockedMargin = traderAcc.lockedMargin > margin
            ? traderAcc.lockedMargin - margin : 0;

        int256 traderReturn = int256(margin) + pnl - int256(penalty);
        if (traderReturn > 0) {
            traderAcc.balance += uint256(traderReturn);
        }

        accounts[msg.sender].balance += liquidatorReward;
        insuranceFund += insurancePortion;

        emit PositionLiquidated(trader, marketId, msg.sender, pnl);
    }

    function _isLiquidatable(address trader, uint256 marketId, uint256 markPrice) internal view returns (bool) {
        Position storage pos = positions[trader][marketId];
        if (!pos.exists || pos.size == 0) return false;

        int256 pnl = _calculatePnl(pos.isLong, pos.entryPrice, markPrice, pos.size);
        int256 equity = int256(pos.margin) + pnl;

        Market storage mkt = markets[marketId];
        uint256 notional = _mul(pos.size, markPrice) / PRECISION;
        uint256 maintenanceMargin = _div(_mul(notional, mkt.maintenanceMarginBps), BPS_BASE);

        return equity <= int256(maintenanceMargin);
    }

    // ══════════════════════════════════════════════════════════
    // ── FUNDING ─────────────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Update funding rate for a market (called periodically)
    function updateFunding(uint256 marketId) external {
        Market storage mkt = markets[marketId];
        require(mkt.active, "Not active");
        require(block.timestamp >= mkt.lastFundingTime + 1 hours, "Too early");

        // Funding rate = (OI_long - OI_short) / (OI_long + OI_short) * base_rate
        uint256 totalOI = mkt.openInterestLong + mkt.openInterestShort;
        if (totalOI == 0) {
            mkt.fundingRate = 0;
        } else {
            int256 imbalance = int256(mkt.openInterestLong) - int256(mkt.openInterestShort);
            // Base funding rate: 0.01% per hour, scaled by imbalance
            int256 baseRate = int256(_div(PRECISION, 10000)); // 0.01%
            mkt.fundingRate += (imbalance * baseRate) / int256(totalOI);
        }

        mkt.lastFundingTime = block.timestamp;
        emit FundingPaid(marketId, mkt.fundingRate);
    }

    // ══════════════════════════════════════════════════════════
    // ── VIEW FUNCTIONS ──────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    function getAccountInfo(address trader) external view returns (
        uint256 balance, uint256 lockedMargin
    ) {
        Account storage acc = accounts[trader];
        return (acc.balance, acc.lockedMargin);
    }

    function getPosition(address trader, uint256 marketId) external view returns (
        bool exists, bool isLong, uint256 size, uint256 entryPrice,
        uint256 margin, uint256 leverage
    ) {
        Position storage pos = positions[trader][marketId];
        return (pos.exists, pos.isLong, pos.size, pos.entryPrice, pos.margin, pos.leverage);
    }

    function getPositionPnl(address trader, uint256 marketId) external view returns (int256) {
        Position storage pos = positions[trader][marketId];
        if (!pos.exists || pos.size == 0) return 0;
        uint256 markPrice = _getMarkPrice(marketId);
        return _calculatePnl(pos.isLong, pos.entryPrice, markPrice, pos.size);
    }

    function getMarketInfo(uint256 marketId) external view returns (
        bytes32 feedId, bool active, uint256 maxLeverage,
        uint256 openInterestLong, uint256 openInterestShort, int256 fundingRate
    ) {
        Market storage m = markets[marketId];
        return (m.feedId, m.active, m.maxLeverage, m.openInterestLong, m.openInterestShort, m.fundingRate);
    }

    // ══════════════════════════════════════════════════════════
    // ── INTERNAL HELPERS ────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    function _getMarkPrice(uint256 marketId) internal view returns (uint256) {
        Market storage mkt = markets[marketId];
        require(oracle.isPriceFresh(mkt.feedId, MAX_STALE), "Stale price");
        return oracle.getNormalizedPrice(mkt.feedId);
    }

    function _calculatePnl(
        bool isLong, uint256 entryPrice, uint256 exitPrice, uint256 size
    ) internal pure returns (int256) {
        if (isLong) {
            return (int256(_mul(size, exitPrice)) - int256(_mul(size, entryPrice))) / int256(PRECISION);
        } else {
            return (int256(_mul(size, entryPrice)) - int256(_mul(size, exitPrice))) / int256(PRECISION);
        }
    }
}
