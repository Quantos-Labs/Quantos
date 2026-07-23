// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPerpEngine {
    function getPosition(address trader, uint256 marketId) external view returns (
        bool exists, bool isLong, uint256 size, uint256 entryPrice, uint256 margin, uint256 leverage
    );
    function getPositionPnl(address trader, uint256 marketId) external view returns (int256);
}

/// @title VaultManager - Vault deposits, withdrawals & copy trading for perp platform
/// @notice Users deposit QTEST to earn yield or copy trade leaders
/// @dev Shares = proportional ownership. Copy trading mirrors leader positions.
contract VaultManager {
    address public owner;
    IERC20  public qtest;
    IPerpEngine public perpEngine;

    // ── Solang 0.3.3 workaround ─────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    uint256 public constant PRECISION = 1e18;
    uint256 public constant BPS_BASE  = 10000;

    // ── Vault ───────────────────────────────────────────────
    struct Vault {
        bool    active;
        string  name;
        string  strategy;       // e.g. "delta-neutral", "momentum"
        address manager;
        uint256 totalDeposits;  // total QTEST deposited
        uint256 totalShares;
        uint256 performanceFeeBps; // e.g. 1000 = 10%
        uint256 managementFeeBps;  // e.g. 200 = 2%
        uint256 minDeposit;
        uint256 maxCapacity;
        uint256 highWaterMark;     // for performance fee calc
        uint256 lastFeeCollection;
    }

    // ── Vault Deposit ───────────────────────────────────────
    struct VaultDeposit {
        uint256 shares;
        uint256 depositAmount;
        uint256 depositTime;
    }

    // ── Copy Trader ─────────────────────────────────────────
    struct CopyTrader {
        bool    active;
        address leader;
        string  displayName;
        uint256 totalFollowers;
        uint256 totalAUM;           // total assets under management
        uint256 profitShareBps;     // e.g. 1000 = 10%
        uint256 minFollowAmount;
        uint256 maxFollowers;
    }

    // ── Copy Position (follower allocation) ─────────────────
    struct CopyAllocation {
        bool    active;
        uint256 copyTraderId;
        uint256 amount;             // QTEST allocated
        uint256 startTime;
    }

    // ── Storage ─────────────────────────────────────────────
    uint256 public vaultCount;
    mapping(uint256 => Vault) public vaults;

    // vaultId => depositor => VaultDeposit
    mapping(uint256 => mapping(address => VaultDeposit)) public vaultDeposits;

    uint256 public copyTraderCount;
    mapping(uint256 => CopyTrader) public copyTraders;

    // follower => copyTraderId => CopyAllocation
    mapping(address => mapping(uint256 => CopyAllocation)) public copyAllocations;

    // leader address => copyTraderId
    mapping(address => uint256) public leaderToCopyTrader;

    // ── Events ──────────────────────────────────────────────
    event VaultCreated(uint256 indexed vaultId, string name, address manager);
    event VaultDeposited(uint256 indexed vaultId, address indexed depositor, uint256 amount, uint256 shares);
    event VaultWithdrawn(uint256 indexed vaultId, address indexed depositor, uint256 amount, uint256 shares);
    event VaultPaused(uint256 indexed vaultId);
    event VaultResumed(uint256 indexed vaultId);
    event FeesCollected(uint256 indexed vaultId, uint256 performanceFee, uint256 managementFee);
    event CopyTraderRegistered(uint256 indexed copyTraderId, address leader, string name);
    event CopyStarted(address indexed follower, uint256 indexed copyTraderId, uint256 amount);
    event CopyStopped(address indexed follower, uint256 indexed copyTraderId, uint256 amount);

    constructor(address _qtest, address _perpEngine) {
        require(_qtest != address(0) && _perpEngine != address(0), "Invalid addresses");
        owner = msg.sender;
        qtest = IERC20(_qtest);
        perpEngine = IPerpEngine(_perpEngine);
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

    function setPerpEngine(address _perpEngine) external onlyOwner {
        require(_perpEngine != address(0), "Invalid");
        perpEngine = IPerpEngine(_perpEngine);
    }

    // ══════════════════════════════════════════════════════════
    // ── VAULT MANAGEMENT ────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    function createVault(
        string calldata name,
        string calldata strategy,
        uint256 performanceFeeBps,
        uint256 managementFeeBps,
        uint256 minDeposit,
        uint256 maxCapacity
    ) external returns (uint256) {
        require(performanceFeeBps <= 3000, "Perf fee too high");   // max 30%
        require(managementFeeBps <= 500, "Mgmt fee too high");     // max 5%

        uint256 id = vaultCount;
        vaults[id] = Vault({
            active:             true,
            name:               name,
            strategy:           strategy,
            manager:            msg.sender,
            totalDeposits:      0,
            totalShares:        0,
            performanceFeeBps:  performanceFeeBps,
            managementFeeBps:   managementFeeBps,
            minDeposit:         minDeposit,
            maxCapacity:        maxCapacity,
            highWaterMark:      PRECISION, // 1:1 initially
            lastFeeCollection:  block.timestamp
        });
        vaultCount = id + 1;
        emit VaultCreated(id, name, msg.sender);
        return id;
    }

    function pauseVault(uint256 vaultId) external {
        Vault storage v = vaults[vaultId];
        require(msg.sender == v.manager || msg.sender == owner, "Not authorized");
        v.active = false;
        emit VaultPaused(vaultId);
    }

    function resumeVault(uint256 vaultId) external {
        Vault storage v = vaults[vaultId];
        require(msg.sender == v.manager || msg.sender == owner, "Not authorized");
        v.active = true;
        emit VaultResumed(vaultId);
    }

    // ══════════════════════════════════════════════════════════
    // ── VAULT DEPOSITS / WITHDRAWALS ────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Deposit QTEST into a vault, receiving shares
    function depositToVault(uint256 vaultId, uint256 amount) external {
        Vault storage v = vaults[vaultId];
        require(v.active, "Vault not active");
        require(amount >= v.minDeposit, "Below minimum");
        require(v.totalDeposits + amount <= v.maxCapacity, "Exceeds capacity");

        require(qtest.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        // Calculate shares: first depositor gets 1:1, then proportional
        uint256 shares;
        if (v.totalShares == 0) {
            shares = amount;
        } else {
            shares = _div(_mul(amount, v.totalShares), v.totalDeposits);
        }
        require(shares > 0, "Zero shares");

        v.totalDeposits += amount;
        v.totalShares += shares;

        VaultDeposit storage dep = vaultDeposits[vaultId][msg.sender];
        dep.shares += shares;
        dep.depositAmount += amount;
        dep.depositTime = block.timestamp;

        emit VaultDeposited(vaultId, msg.sender, amount, shares);
    }

    /// @notice Withdraw from vault by burning shares
    function withdrawFromVault(uint256 vaultId, uint256 sharesToBurn) external {
        Vault storage v = vaults[vaultId];
        VaultDeposit storage dep = vaultDeposits[vaultId][msg.sender];
        require(dep.shares >= sharesToBurn && sharesToBurn > 0, "Insufficient shares");

        // Calculate QTEST amount for shares
        uint256 amount = _div(_mul(sharesToBurn, v.totalDeposits), v.totalShares);
        require(amount > 0, "Zero amount");

        v.totalShares -= sharesToBurn;
        v.totalDeposits = v.totalDeposits > amount ? v.totalDeposits - amount : 0;
        dep.shares -= sharesToBurn;
        dep.depositAmount = dep.depositAmount > amount ? dep.depositAmount - amount : 0;

        require(qtest.transfer(msg.sender, amount), "Transfer failed");
        emit VaultWithdrawn(vaultId, msg.sender, amount, sharesToBurn);
    }

    /// @notice Collect performance + management fees (vault manager only)
    function collectFees(uint256 vaultId) external {
        Vault storage v = vaults[vaultId];
        require(msg.sender == v.manager, "Not manager");
        require(v.totalDeposits > 0 && v.totalShares > 0, "Empty vault");

        // Management fee: pro-rata annual fee based on time elapsed
        uint256 elapsed = block.timestamp - v.lastFeeCollection;
        uint256 annualFraction = _div(_mul(elapsed, PRECISION), 365 days);
        uint256 mgmtFee = _div(_mul(_mul(v.totalDeposits, v.managementFeeBps), annualFraction), _mul(BPS_BASE, PRECISION));

        // Performance fee: only on gains above high water mark
        uint256 currentNav = v.totalShares > 0
            ? _div(_mul(v.totalDeposits, PRECISION), v.totalShares)
            : PRECISION;
        uint256 perfFee = 0;
        if (currentNav > v.highWaterMark) {
            uint256 gain = currentNav - v.highWaterMark;
            perfFee = _div(_mul(_mul(gain, v.totalShares), v.performanceFeeBps), _mul(BPS_BASE, PRECISION));
            v.highWaterMark = currentNav;
        }

        uint256 totalFee = mgmtFee + perfFee;
        if (totalFee > 0 && totalFee <= v.totalDeposits) {
            v.totalDeposits -= totalFee;
            require(qtest.transfer(v.manager, totalFee), "Fee transfer failed");
        }

        v.lastFeeCollection = block.timestamp;
        emit FeesCollected(vaultId, perfFee, mgmtFee);
    }

    // ══════════════════════════════════════════════════════════
    // ── COPY TRADING ────────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    /// @notice Register as a copy-trade leader
    function registerCopyTrader(
        string calldata displayName,
        uint256 profitShareBps,
        uint256 minFollowAmount,
        uint256 maxFollowers
    ) external returns (uint256) {
        require(profitShareBps <= 3000, "Profit share too high"); // max 30%
        require(maxFollowers > 0, "Max followers must be > 0");
        require(leaderToCopyTrader[msg.sender] == 0 || !copyTraders[leaderToCopyTrader[msg.sender]].active,
            "Already registered");

        uint256 id = copyTraderCount;
        copyTraders[id] = CopyTrader({
            active:          true,
            leader:          msg.sender,
            displayName:     displayName,
            totalFollowers:  0,
            totalAUM:        0,
            profitShareBps:  profitShareBps,
            minFollowAmount: minFollowAmount,
            maxFollowers:    maxFollowers
        });
        leaderToCopyTrader[msg.sender] = id;
        copyTraderCount = id + 1;

        emit CopyTraderRegistered(id, msg.sender, displayName);
        return id;
    }

    /// @notice Start copy trading a leader
    function startCopyTrading(uint256 copyTraderId, uint256 amount) external {
        CopyTrader storage ct = copyTraders[copyTraderId];
        require(ct.active, "Not active");
        require(amount >= ct.minFollowAmount, "Below minimum");
        require(ct.totalFollowers < ct.maxFollowers, "Max followers reached");
        require(ct.leader != msg.sender, "Cannot copy yourself");

        CopyAllocation storage ca = copyAllocations[msg.sender][copyTraderId];
        require(!ca.active, "Already copying");

        require(qtest.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        ca.active = true;
        ca.copyTraderId = copyTraderId;
        ca.amount = amount;
        ca.startTime = block.timestamp;

        ct.totalFollowers += 1;
        ct.totalAUM += amount;

        emit CopyStarted(msg.sender, copyTraderId, amount);
    }

    /// @notice Stop copy trading and withdraw funds
    function stopCopyTrading(uint256 copyTraderId) external {
        CopyAllocation storage ca = copyAllocations[msg.sender][copyTraderId];
        require(ca.active, "Not copying");

        CopyTrader storage ct = copyTraders[copyTraderId];
        uint256 amount = ca.amount;

        // Calculate profit share if any gains
        // For simplicity, profit is tracked off-chain; on-chain just returns principal
        // Profit sharing handled by backend when settling copy positions

        ca.active = false;
        ca.amount = 0;

        ct.totalFollowers = ct.totalFollowers > 0 ? ct.totalFollowers - 1 : 0;
        ct.totalAUM = ct.totalAUM > amount ? ct.totalAUM - amount : 0;

        require(qtest.transfer(msg.sender, amount), "Transfer failed");
        emit CopyStopped(msg.sender, copyTraderId, amount);
    }

    /// @notice Deactivate copy trader profile
    function deactivateCopyTrader() external {
        uint256 id = leaderToCopyTrader[msg.sender];
        CopyTrader storage ct = copyTraders[id];
        require(ct.leader == msg.sender && ct.active, "Not your profile");
        require(ct.totalFollowers == 0, "Has active followers");
        ct.active = false;
    }

    // ══════════════════════════════════════════════════════════
    // ── VIEW FUNCTIONS ──────────────────────────────────────
    // ══════════════════════════════════════════════════════════

    function getVaultInfo(uint256 vaultId) external view returns (
        bool active, string memory name, string memory strategy,
        address manager, uint256 totalDeposits, uint256 totalShares
    ) {
        Vault storage v = vaults[vaultId];
        return (v.active, v.name, v.strategy, v.manager, v.totalDeposits, v.totalShares);
    }

    function getVaultNav(uint256 vaultId) external view returns (uint256) {
        Vault storage v = vaults[vaultId];
        if (v.totalShares == 0) return PRECISION;
        return _div(_mul(v.totalDeposits, PRECISION), v.totalShares);
    }

    function getUserShares(uint256 vaultId, address user) external view returns (
        uint256 shares, uint256 depositAmount, uint256 currentValue
    ) {
        VaultDeposit storage dep = vaultDeposits[vaultId][user];
        Vault storage v = vaults[vaultId];
        uint256 value = v.totalShares > 0
            ? _div(_mul(dep.shares, v.totalDeposits), v.totalShares)
            : dep.depositAmount;
        return (dep.shares, dep.depositAmount, value);
    }

    function getCopyTraderInfo(uint256 id) external view returns (
        bool active, address leader, string memory displayName,
        uint256 totalFollowers, uint256 totalAUM, uint256 profitShareBps
    ) {
        CopyTrader storage ct = copyTraders[id];
        return (ct.active, ct.leader, ct.displayName, ct.totalFollowers, ct.totalAUM, ct.profitShareBps);
    }

    function getCopyAllocation(address follower, uint256 copyTraderId) external view returns (
        bool active, uint256 amount, uint256 startTime
    ) {
        CopyAllocation storage ca = copyAllocations[follower][copyTraderId];
        return (ca.active, ca.amount, ca.startTime);
    }
}
