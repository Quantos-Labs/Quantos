// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVybssLToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface IVybssDebtToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// @title VybssLendingPool - Core lending protocol
/// @notice Multi-asset pool with variable interest rates, collateral management, and liquidations.
/// @dev Interest rate model: variable rate based on utilization with a kink.
///      - Below optimal utilization (80%): rates scale linearly
///      - Above optimal utilization: rates spike sharply to incentivize repayment
contract VybssLendingPool {
    address public owner;
    uint256 public constant SECONDS_PER_YEAR = 365 days;
    uint256 public constant PRECISION = 1e18;
    uint256 public constant PERCENTAGE_FACTOR = 10000; // basis points

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Reserve configuration ───────────────────────────────────
    struct ReserveConfig {
        bool isActive;
        bool canBeCollateral;
        bool canBeBorrowed;
        bool isFrozen;         // Frozen = no new supply/borrow, only repay/withdraw
        bool flashLoanEnabled; // Whether flash loans are enabled for this reserve
        uint256 ltvBps;        // Loan-to-Value in basis points (e.g., 8000 = 80%)
        uint256 liquidationThresholdBps; // e.g., 8500 = 85%
        uint256 liquidationPenaltyBps;   // e.g., 500 = 5%
        uint256 reserveFactorBps;        // Protocol cut of interest (e.g., 1000 = 10%)
        uint256 supplyCap;     // Max supply (0 = unlimited)
        uint256 borrowCap;     // Max borrow (0 = unlimited)
    }

    // ── Interest rate model parameters ──────────────────────────
    struct InterestRateModel {
        uint256 optimalUtilizationBps;   // e.g., 8000 = 80%
        uint256 baseRateBps;             // Base rate at 0% utilization
        uint256 slopeRate1Bps;           // Rate increase per unit util below optimal
        uint256 slopeRate2Bps;           // Rate increase per unit util above optimal
    }

    // ── Reserve state ───────────────────────────────────────────
    struct ReserveState {
        address underlyingAsset;
        address lTokenAddress;
        address debtTokenAddress;
        uint256 liquidityIndex;  // Scaled 1e18, grows with supply APY
        uint256 borrowIndex;     // Scaled 1e18, grows with borrow APY
        uint256 lastUpdateTimestamp;
        uint256 totalBorrowed;   // Total borrowed in underlying units
        uint256 accruedProtocolFees;
    }

    // ── User collateral tracking ────────────────────────────────
    struct UserConfig {
        uint256 collateralBitmap; // bit i = user is using reserve i as collateral
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public reserveCount;
    mapping(uint256 => ReserveConfig) public reserveConfigs;
    mapping(uint256 => InterestRateModel) public interestRateModels;
    mapping(uint256 => ReserveState) public reserveStates;
    mapping(address => uint256) public assetToReserveId; // underlying → reserveId (1-indexed, 0=not found)
    mapping(address => UserConfig) internal userConfigs;

    // Flash loan fee in basis points
    uint256 public flashLoanPremiumTotalBps = 9; // 0.09% total premium
    uint256 public flashLoanPremiumToProtocolBps = 3000; // 30% of premium goes to protocol

    // ── Events ──────────────────────────────────────────────────
    event ReserveInitialized(uint256 indexed reserveId, address indexed asset, address lToken, address debtToken);
    event Supply(address indexed user, uint256 indexed reserveId, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed reserveId, uint256 amount);
    event Borrow(address indexed user, uint256 indexed reserveId, uint256 amount);
    event Repay(address indexed user, uint256 indexed reserveId, uint256 amount);
    event Liquidation(
        address indexed liquidator,
        address indexed user,
        uint256 collateralReserveId,
        uint256 debtReserveId,
        uint256 debtRepaid,
        uint256 collateralSeized
    );
    event FlashLoan(address indexed receiver, uint256 indexed reserveId, uint256 amount, uint256 fee);
    event CollateralToggled(address indexed user, uint256 indexed reserveId, bool enabled);
    event ReserveConfigUpdated(uint256 indexed reserveId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ═══════════════════════════════════════════════════════════
    //                     ADMIN FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    /// @notice Initialize a new reserve (asset market)
    function initReserve(
        address _asset,
        address _lToken,
        address _debtToken,
        uint256 _ltvBps,
        uint256 _liquidationThresholdBps,
        uint256 _liquidationPenaltyBps,
        uint256 _reserveFactorBps,
        bool _canBeCollateral,
        bool _canBeBorrowed
    ) external onlyOwner {
        require(assetToReserveId[_asset] == 0, "Already initialized");
        require(_ltvBps <= _liquidationThresholdBps, "LTV > threshold");
        require(_liquidationThresholdBps <= PERCENTAGE_FACTOR, "Threshold > 100%");

        reserveCount += 1;
        uint256 rid = reserveCount;
        assetToReserveId[_asset] = rid;

        reserveConfigs[rid] = ReserveConfig({
            isActive: true,
            canBeCollateral: _canBeCollateral,
            canBeBorrowed: _canBeBorrowed,
            isFrozen: false,
            flashLoanEnabled: true,
            ltvBps: _ltvBps,
            liquidationThresholdBps: _liquidationThresholdBps,
            liquidationPenaltyBps: _liquidationPenaltyBps,
            reserveFactorBps: _reserveFactorBps,
            supplyCap: 0,
            borrowCap: 0
        });

        // Default interest rate model: base 2%, slope1 4%, slope2 75%, optimal 80%
        interestRateModels[rid] = InterestRateModel({
            optimalUtilizationBps: 8000,
            baseRateBps: 200,
            slopeRate1Bps: 400,
            slopeRate2Bps: 7500
        });

        reserveStates[rid] = ReserveState({
            underlyingAsset: _asset,
            lTokenAddress: _lToken,
            debtTokenAddress: _debtToken,
            liquidityIndex: PRECISION,
            borrowIndex: PRECISION,
            lastUpdateTimestamp: block.timestamp,
            totalBorrowed: 0,
            accruedProtocolFees: 0
        });

        emit ReserveInitialized(rid, _asset, _lToken, _debtToken);
    }

    /// @notice Update reserve configuration
    function setReserveConfig(
        uint256 _reserveId,
        uint256 _ltvBps,
        uint256 _liquidationThresholdBps,
        uint256 _liquidationPenaltyBps,
        uint256 _reserveFactorBps,
        uint256 _supplyCap,
        uint256 _borrowCap,
        bool _canBeCollateral,
        bool _canBeBorrowed,
        bool _isFrozen
    ) external onlyOwner {
        require(_reserveId > 0 && _reserveId <= reserveCount, "Invalid reserve");
        ReserveConfig storage cfg = reserveConfigs[_reserveId];
        cfg.ltvBps = _ltvBps;
        cfg.liquidationThresholdBps = _liquidationThresholdBps;
        cfg.liquidationPenaltyBps = _liquidationPenaltyBps;
        cfg.reserveFactorBps = _reserveFactorBps;
        cfg.supplyCap = _supplyCap;
        cfg.borrowCap = _borrowCap;
        cfg.canBeCollateral = _canBeCollateral;
        cfg.canBeBorrowed = _canBeBorrowed;
        cfg.isFrozen = _isFrozen;
        emit ReserveConfigUpdated(_reserveId);
    }

    /// @notice Set interest rate model for a reserve
    function setInterestRateModel(
        uint256 _reserveId,
        uint256 _optimalUtilBps,
        uint256 _baseRateBps,
        uint256 _slope1Bps,
        uint256 _slope2Bps
    ) external onlyOwner {
        require(_reserveId > 0 && _reserveId <= reserveCount, "Invalid reserve");
        interestRateModels[_reserveId] = InterestRateModel({
            optimalUtilizationBps: _optimalUtilBps,
            baseRateBps: _baseRateBps,
            slopeRate1Bps: _slope1Bps,
            slopeRate2Bps: _slope2Bps
        });
    }

    function setFlashLoanPremium(uint256 _totalBps, uint256 _toProtocolBps) external onlyOwner {
        require(_totalBps <= 100, "Premium too high"); // Max 1%
        require(_toProtocolBps <= PERCENTAGE_FACTOR, "Invalid protocol share");
        flashLoanPremiumTotalBps = _totalBps;
        flashLoanPremiumToProtocolBps = _toProtocolBps;
    }

    function setReserveFlashLoan(uint256 _reserveId, bool _enabled) external onlyOwner {
        reserveConfigs[_reserveId].flashLoanEnabled = _enabled;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // ═══════════════════════════════════════════════════════════
    //                     CORE ACTIONS
    // ═══════════════════════════════════════════════════════════

    /// @notice Supply underlying asset to earn interest
    /// @param _reserveId The reserve to supply to
    /// @param _amount Amount of underlying to supply
    function supply(uint256 _reserveId, uint256 _amount) external {
        require(_amount > 0, "Zero amount");
        ReserveConfig storage cfg = reserveConfigs[_reserveId];
        ReserveState storage state = reserveStates[_reserveId];
        require(cfg.isActive && !cfg.isFrozen, "Reserve not active");

        _accrueInterest(_reserveId);

        // Check supply cap
        if (cfg.supplyCap > 0) {
            uint256 totalSupplied = IERC20(state.underlyingAsset).balanceOf(address(this));
            require(totalSupplied + _amount <= cfg.supplyCap, "Supply cap reached");
        }

        // Transfer underlying from user
        require(
            IERC20(state.underlyingAsset).transferFrom(msg.sender, address(this), _amount),
            "Transfer failed"
        );

        // Calculate shares: amount / liquidityIndex
        uint256 sharesToMint = _div(_mul(_amount, PRECISION), state.liquidityIndex);

        // Mint lTokens
        IVybssLToken(state.lTokenAddress).mint(msg.sender, sharesToMint);

        // Auto-enable as collateral if eligible
        if (cfg.canBeCollateral) {
            _setCollateral(msg.sender, _reserveId, true);
        }

        emit Supply(msg.sender, _reserveId, _amount);
    }

    /// @notice Withdraw supplied assets
    /// @param _reserveId The reserve to withdraw from
    /// @param _amount Amount of underlying to withdraw (type(uint256).max for all)
    function withdraw(uint256 _reserveId, uint256 _amount) external {
        ReserveState storage state = reserveStates[_reserveId];
        require(reserveConfigs[_reserveId].isActive, "Reserve not active");

        _accrueInterest(_reserveId);

        uint256 userShares = IVybssLToken(state.lTokenAddress).balanceOf(msg.sender);
        uint256 userBalance = _div(_mul(userShares, state.liquidityIndex), PRECISION);

        uint256 withdrawAmount = _amount;
        uint256 sharesToBurn;
        if (_amount == type(uint256).max) {
            withdrawAmount = userBalance;
            sharesToBurn = userShares;
        } else {
            require(_amount <= userBalance, "Exceeds balance");
            sharesToBurn = _div(_mul(_amount, PRECISION), state.liquidityIndex);
            if (sharesToBurn > userShares) sharesToBurn = userShares;
        }

        require(withdrawAmount > 0, "Zero withdraw");

        // Burn lTokens
        IVybssLToken(state.lTokenAddress).burn(msg.sender, sharesToBurn);

        // Check health factor after withdrawal
        if (_hasAnyDebt(msg.sender)) {
            require(_getUserHealthFactor(msg.sender) >= PRECISION, "Undercollateralized");
        }

        // Transfer underlying to user
        require(
            IERC20(state.underlyingAsset).transfer(msg.sender, withdrawAmount),
            "Transfer failed"
        );

        emit Withdraw(msg.sender, _reserveId, withdrawAmount);
    }

    /// @notice Borrow underlying assets
    /// @param _reserveId The reserve to borrow from
    /// @param _amount Amount of underlying to borrow
    function borrow(uint256 _reserveId, uint256 _amount) external {
        require(_amount > 0, "Zero amount");
        ReserveConfig storage cfg = reserveConfigs[_reserveId];
        ReserveState storage state = reserveStates[_reserveId];
        require(cfg.isActive && !cfg.isFrozen && cfg.canBeBorrowed, "Cannot borrow");

        _accrueInterest(_reserveId);

        // Check borrow cap
        if (cfg.borrowCap > 0) {
            require(state.totalBorrowed + _amount <= cfg.borrowCap, "Borrow cap reached");
        }

        // Check available liquidity
        uint256 available = IERC20(state.underlyingAsset).balanceOf(address(this));
        require(_amount <= available, "Insufficient liquidity");

        // Mint debt tokens: amount / borrowIndex
        uint256 debtShares = _div(_mul(_amount, PRECISION), state.borrowIndex);
        IVybssDebtToken(state.debtTokenAddress).mint(msg.sender, debtShares);

        // Update total borrowed
        state.totalBorrowed += _amount;

        // Check health factor
        require(_getUserHealthFactor(msg.sender) >= PRECISION, "Undercollateralized");

        // Transfer underlying to borrower
        require(
            IERC20(state.underlyingAsset).transfer(msg.sender, _amount),
            "Transfer failed"
        );

        emit Borrow(msg.sender, _reserveId, _amount);
    }

    /// @notice Repay borrowed assets
    /// @param _reserveId The reserve to repay
    /// @param _amount Amount to repay (type(uint256).max for full repay)
    function repay(uint256 _reserveId, uint256 _amount) external {
        ReserveState storage state = reserveStates[_reserveId];
        require(reserveConfigs[_reserveId].isActive, "Reserve not active");

        _accrueInterest(_reserveId);

        uint256 userDebtShares = IVybssDebtToken(state.debtTokenAddress).balanceOf(msg.sender);
        require(userDebtShares > 0, "No debt");

        uint256 userDebt = _div(_mul(userDebtShares, state.borrowIndex), PRECISION);

        uint256 repayAmount = _amount;
        uint256 debtSharesToBurn;
        if (_amount == type(uint256).max) {
            repayAmount = userDebt;
            debtSharesToBurn = userDebtShares;
        } else {
            require(_amount <= userDebt, "Exceeds debt");
            debtSharesToBurn = _div(_mul(_amount, PRECISION), state.borrowIndex);
            if (debtSharesToBurn > userDebtShares) debtSharesToBurn = userDebtShares;
        }

        require(repayAmount > 0, "Zero repay");

        // Transfer underlying from repayer
        require(
            IERC20(state.underlyingAsset).transferFrom(msg.sender, address(this), repayAmount),
            "Transfer failed"
        );

        // Burn debt tokens
        IVybssDebtToken(state.debtTokenAddress).burn(msg.sender, debtSharesToBurn);

        // Update total borrowed
        if (repayAmount > state.totalBorrowed) {
            state.totalBorrowed = 0;
        } else {
            state.totalBorrowed -= repayAmount;
        }

        emit Repay(msg.sender, _reserveId, repayAmount);
    }

    // ═══════════════════════════════════════════════════════════
    //                      LIQUIDATION
    // ═══════════════════════════════════════════════════════════

    /// @notice Liquidate an unhealthy position
    /// @param _user The borrower to liquidate
    /// @param _debtReserveId The reserve of the debt to repay
    /// @param _collateralReserveId The reserve of the collateral to seize
    /// @param _debtAmount Amount of debt to repay (max 50% of user's debt in that reserve)
    function liquidate(
        address _user,
        uint256 _debtReserveId,
        uint256 _collateralReserveId,
        uint256 _debtAmount
    ) external {
        require(_user != msg.sender, "Cannot self-liquidate");

        _accrueInterest(_debtReserveId);
        _accrueInterest(_collateralReserveId);

        // Check user is undercollateralized (HF < 1.0)
        uint256 hf = _getUserHealthFactor(_user);
        require(hf < PRECISION, "Position healthy");

        ReserveState storage debtState = reserveStates[_debtReserveId];
        ReserveState storage collState = reserveStates[_collateralReserveId];

        // Max liquidatable = 50% of user's debt in this reserve (close factor)
        uint256 userDebtShares = IVybssDebtToken(debtState.debtTokenAddress).balanceOf(_user);
        uint256 userDebt = _div(_mul(userDebtShares, debtState.borrowIndex), PRECISION);
        uint256 maxLiquidatable = _div(userDebt, 2); // 50% close factor
        uint256 actualDebtRepay = _debtAmount > maxLiquidatable ? maxLiquidatable : _debtAmount;
        require(actualDebtRepay > 0, "Zero liquidation");

        // Calculate collateral to seize:
        // collateralSeized = debtRepaid * (1 + liquidationPenalty)
        // Note: In production this would use an oracle for cross-asset pricing.
        // For same-denomination assets or 1:1 pricing:
        uint256 penaltyBps = reserveConfigs[_collateralReserveId].liquidationPenaltyBps;
        uint256 collateralToSeize = _div(
            _mul(actualDebtRepay, PERCENTAGE_FACTOR + penaltyBps),
            PERCENTAGE_FACTOR
        );

        // Verify user has enough collateral
        uint256 userCollShares = IVybssLToken(collState.lTokenAddress).balanceOf(_user);
        uint256 userCollBalance = _div(_mul(userCollShares, collState.liquidityIndex), PRECISION);
        if (collateralToSeize > userCollBalance) {
            collateralToSeize = userCollBalance;
        }

        // Liquidator pays the debt
        require(
            IERC20(debtState.underlyingAsset).transferFrom(msg.sender, address(this), actualDebtRepay),
            "Transfer failed"
        );

        // Burn debt tokens from user
        uint256 debtSharesToBurn = _div(_mul(actualDebtRepay, PRECISION), debtState.borrowIndex);
        if (debtSharesToBurn > userDebtShares) debtSharesToBurn = userDebtShares;
        IVybssDebtToken(debtState.debtTokenAddress).burn(_user, debtSharesToBurn);

        // Reduce total borrowed
        if (actualDebtRepay > debtState.totalBorrowed) {
            debtState.totalBorrowed = 0;
        } else {
            debtState.totalBorrowed -= actualDebtRepay;
        }

        // Transfer collateral lTokens from user to liquidator
        uint256 collSharesSeized = _div(_mul(collateralToSeize, PRECISION), collState.liquidityIndex);
        if (collSharesSeized > userCollShares) collSharesSeized = userCollShares;
        IVybssLToken(collState.lTokenAddress).burn(_user, collSharesSeized);

        // Transfer underlying collateral to liquidator
        require(
            IERC20(collState.underlyingAsset).transfer(msg.sender, collateralToSeize),
            "Transfer failed"
        );

        emit Liquidation(msg.sender, _user, _collateralReserveId, _debtReserveId, actualDebtRepay, collateralToSeize);
    }

    // ═══════════════════════════════════════════════════════════
    //                      FLASH LOANS
    // ═══════════════════════════════════════════════════════════

    /// @notice Execute a flash loan — borrow any amount without collateral,
    ///         repay principal + premium within the same transaction.
    /// @param _reserveId Reserve to borrow from
    /// @param _amount Amount to borrow
    /// @param _receiver Contract implementing IFlashLoanReceiver
    /// @param _params Arbitrary data forwarded to the receiver's callback
    function flashLoan(
        uint256 _reserveId,
        uint256 _amount,
        address _receiver,
        bytes calldata _params
    ) external {
        require(_amount > 0, "Zero amount");
        ReserveConfig storage config = reserveConfigs[_reserveId];
        ReserveState storage state = reserveStates[_reserveId];
        require(config.isActive, "Reserve not active");
        require(config.flashLoanEnabled, "Flash loan disabled for reserve");

        uint256 premium = _div(_mul(_amount, flashLoanPremiumTotalBps), PERCENTAGE_FACTOR);
        uint256 balanceBefore = IERC20(state.underlyingAsset).balanceOf(address(this));
        require(balanceBefore >= _amount, "Not enough liquidity");

        // 1. Transfer borrowed amount to receiver
        require(
            IERC20(state.underlyingAsset).transfer(_receiver, _amount),
            "Transfer to receiver failed"
        );

        // 2. Execute receiver callback — receiver must repay amount + premium
        bool success = IFlashLoanReceiver(_receiver).executeOperation(
            state.underlyingAsset,
            _amount,
            premium,
            msg.sender, // initiator
            _params
        );
        require(success, "Invalid flash loan executor return");

        // 3. Verify the pool received repayment (principal + premium)
        uint256 balanceAfter = IERC20(state.underlyingAsset).balanceOf(address(this));
        require(balanceAfter >= balanceBefore + premium, "Flash loan not repaid");

        // 4. Split premium: protocol share + LP share
        uint256 premiumToProtocol = _div(_mul(premium, flashLoanPremiumToProtocolBps), PERCENTAGE_FACTOR);
        state.accruedProtocolFees += premiumToProtocol;
        // Remaining premium (premium - premiumToProtocol) stays in the pool for LPs

        emit FlashLoan(_receiver, _reserveId, _amount, premium);
    }

    // ═══════════════════════════════════════════════════════════
    //                  COLLATERAL MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /// @notice Toggle collateral status for a reserve
    function setUserCollateral(uint256 _reserveId, bool _enabled) external {
        require(_reserveId > 0 && _reserveId <= reserveCount, "Invalid reserve");
        require(reserveConfigs[_reserveId].canBeCollateral, "Cannot be collateral");

        if (!_enabled && _hasAnyDebt(msg.sender)) {
            // Disabling collateral — verify still healthy
            _setCollateral(msg.sender, _reserveId, false);
            require(_getUserHealthFactor(msg.sender) >= PRECISION, "Would be undercollateralized");
        } else {
            _setCollateral(msg.sender, _reserveId, _enabled);
        }

        emit CollateralToggled(msg.sender, _reserveId, _enabled);
    }

    // ═══════════════════════════════════════════════════════════
    //              PUBLIC INTEREST ACCRUAL (keeper)
    // ═══════════════════════════════════════════════════════════

    /// @notice Permissionless: anyone can poke a reserve to accrue interest
    function accrueInterest(uint256 _reserveId) external {
        require(_reserveId > 0 && _reserveId <= reserveCount, "Invalid reserve");
        _accrueInterest(_reserveId);
    }

    // ═══════════════════════════════════════════════════════════
    //                    VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    /// @notice Get reserve data for a reserve ID
    function getReserveData(uint256 _reserveId) external view returns (
        address underlyingAsset,
        address lTokenAddress,
        address debtTokenAddress,
        uint256 liquidityIndex,
        uint256 borrowIndex,
        uint256 totalBorrowed,
        uint256 lastUpdateTimestamp,
        uint256 accruedProtocolFees
    ) {
        ReserveState memory s = reserveStates[_reserveId];
        return (
            s.underlyingAsset,
            s.lTokenAddress,
            s.debtTokenAddress,
            s.liquidityIndex,
            s.borrowIndex,
            s.totalBorrowed,
            s.lastUpdateTimestamp,
            s.accruedProtocolFees
        );
    }

    /// @notice Get current interest rates for a reserve
    function getReserveRates(uint256 _reserveId) external view returns (
        uint256 supplyRateBps,
        uint256 borrowRateBps,
        uint256 utilizationBps
    ) {
        ReserveState memory state = reserveStates[_reserveId];
        uint256 totalLiquidity = IERC20(state.underlyingAsset).balanceOf(address(this));
        uint256 totalDebt = state.totalBorrowed;
        uint256 util = _calculateUtilization(totalLiquidity, totalDebt);
        uint256 bRate = _calculateBorrowRate(_reserveId, util);
        uint256 sRate = _calculateSupplyRate(bRate, util, reserveConfigs[_reserveId].reserveFactorBps);
        return (sRate, bRate, util);
    }

    /// @notice Get a user's overall health factor
    /// @return Health factor scaled by 1e18. < 1e18 means liquidatable.
    function getUserHealthFactor(address _user) external view returns (uint256) {
        return _getUserHealthFactor(_user);
    }

    /// @notice Get user supply balance in underlying for a reserve
    function getUserSupplyBalance(uint256 _reserveId, address _user) external view returns (uint256) {
        ReserveState memory state = reserveStates[_reserveId];
        uint256 shares = IVybssLToken(state.lTokenAddress).balanceOf(_user);
        if (shares == 0) return 0;
        return _div(_mul(shares, state.liquidityIndex), PRECISION);
    }

    /// @notice Get user debt balance in underlying for a reserve
    function getUserDebtBalance(uint256 _reserveId, address _user) external view returns (uint256) {
        ReserveState memory state = reserveStates[_reserveId];
        uint256 shares = IVybssDebtToken(state.debtTokenAddress).balanceOf(_user);
        if (shares == 0) return 0;
        return _div(_mul(shares, state.borrowIndex), PRECISION);
    }

    /// @notice Check if a user has a reserve enabled as collateral
    function isUserCollateral(address _user, uint256 _reserveId) external view returns (bool) {
        return _isCollateral(_user, _reserveId);
    }

    /// @notice Calculate the user's total collateral and debt values
    /// @return totalCollateralValue Total value of collateral weighted by LTV
    /// @return totalDebtValue Total value of debt
    function getUserAccountData(address _user) external view returns (
        uint256 totalCollateralValue,
        uint256 totalDebtValue,
        uint256 availableBorrow,
        uint256 healthFactor
    ) {
        (uint256 collVal, uint256 debtVal) = _getUserTotals(_user);
        uint256 hf = debtVal == 0 ? type(uint256).max : _div(_mul(collVal, PRECISION), debtVal);
        uint256 availBorrow = collVal > debtVal ? collVal - debtVal : 0;
        return (collVal, debtVal, availBorrow, hf);
    }

    // ═══════════════════════════════════════════════════════════
    //                  INTERNAL - INTEREST
    // ═══════════════════════════════════════════════════════════

    function _accrueInterest(uint256 _reserveId) internal {
        ReserveState storage state = reserveStates[_reserveId];
        if (block.timestamp <= state.lastUpdateTimestamp) return;

        uint256 totalLiquidity = IERC20(state.underlyingAsset).balanceOf(address(this));
        uint256 totalDebt = state.totalBorrowed;

        if (totalDebt == 0) {
            state.lastUpdateTimestamp = block.timestamp;
            return;
        }

        uint256 utilization = _calculateUtilization(totalLiquidity, totalDebt);
        uint256 borrowRate = _calculateBorrowRate(_reserveId, utilization);

        uint256 timeElapsed = block.timestamp - state.lastUpdateTimestamp;

        // borrowIndex += borrowIndex * borrowRate * timeElapsed / SECONDS_PER_YEAR / PERCENTAGE_FACTOR
        uint256 borrowAccrual = _div(
            _mul(_mul(state.borrowIndex, borrowRate), timeElapsed),
            _mul(SECONDS_PER_YEAR, PERCENTAGE_FACTOR)
        );
        state.borrowIndex += borrowAccrual;

        // Update total borrowed based on new index
        uint256 totalDebtShares = IVybssDebtToken(state.debtTokenAddress).totalSupply();
        state.totalBorrowed = _div(_mul(totalDebtShares, state.borrowIndex), PRECISION);

        // Supply rate factors in reserve cut
        uint256 supplyRate = _calculateSupplyRate(borrowRate, utilization, reserveConfigs[_reserveId].reserveFactorBps);
        uint256 supplyAccrual = _div(
            _mul(_mul(state.liquidityIndex, supplyRate), timeElapsed),
            _mul(SECONDS_PER_YEAR, PERCENTAGE_FACTOR)
        );
        state.liquidityIndex += supplyAccrual;

        // Protocol fee accrual
        uint256 protocolCut = _div(
            _mul(borrowAccrual, reserveConfigs[_reserveId].reserveFactorBps),
            PERCENTAGE_FACTOR
        );
        state.accruedProtocolFees += _div(_mul(protocolCut, totalDebt), PRECISION);

        state.lastUpdateTimestamp = block.timestamp;
    }

    function _calculateUtilization(uint256 _liquidity, uint256 _debt) internal pure returns (uint256) {
        uint256 total = _liquidity + _debt;
        if (total == 0) return 0;
        return _div(_mul(_debt, PERCENTAGE_FACTOR), total);
    }

    function _calculateBorrowRate(uint256 _reserveId, uint256 _utilization) internal view returns (uint256) {
        InterestRateModel memory model = interestRateModels[_reserveId];

        if (_utilization <= model.optimalUtilizationBps) {
            // Linear scaling below optimal
            return model.baseRateBps + _div(
                _mul(_utilization, model.slopeRate1Bps),
                model.optimalUtilizationBps
            );
        } else {
            // Steep scaling above optimal (kink)
            uint256 baseAtOptimal = model.baseRateBps + model.slopeRate1Bps;
            uint256 excessUtil = _utilization - model.optimalUtilizationBps;
            uint256 excessRange = PERCENTAGE_FACTOR - model.optimalUtilizationBps;
            return baseAtOptimal + _div(
                _mul(excessUtil, model.slopeRate2Bps),
                excessRange
            );
        }
    }

    function _calculateSupplyRate(
        uint256 _borrowRate,
        uint256 _utilization,
        uint256 _reserveFactorBps
    ) internal pure returns (uint256) {
        // supplyRate = borrowRate * utilization * (1 - reserveFactor)
        uint256 a = _mul(_borrowRate, _utilization);
        uint256 b = PERCENTAGE_FACTOR - _reserveFactorBps;
        return _div(_mul(a, b), _mul(PERCENTAGE_FACTOR, PERCENTAGE_FACTOR));
    }

    // ═══════════════════════════════════════════════════════════
    //                INTERNAL - HEALTH FACTOR
    // ═══════════════════════════════════════════════════════════

    function _getUserTotals(address _user) internal view returns (uint256 totalCollateral, uint256 totalDebt) {
        for (uint256 i = 1; i <= reserveCount; i++) {
            ReserveState memory state = reserveStates[i];
            ReserveConfig memory cfg = reserveConfigs[i];

            // Collateral
            if (_isCollateral(_user, i)) {
                uint256 supplyShares = IVybssLToken(state.lTokenAddress).balanceOf(_user);
                if (supplyShares > 0) {
                    uint256 supplyBalance = _div(_mul(supplyShares, state.liquidityIndex), PRECISION);
                    // Weight by liquidation threshold
                    totalCollateral += _div(
                        _mul(supplyBalance, cfg.liquidationThresholdBps),
                        PERCENTAGE_FACTOR
                    );
                }
            }

            // Debt
            uint256 debtShares = IVybssDebtToken(state.debtTokenAddress).balanceOf(_user);
            if (debtShares > 0) {
                totalDebt += _div(_mul(debtShares, state.borrowIndex), PRECISION);
            }
        }
    }

    function _getUserHealthFactor(address _user) internal view returns (uint256) {
        (uint256 collVal, uint256 debtVal) = _getUserTotals(_user);
        if (debtVal == 0) return type(uint256).max;
        return _div(_mul(collVal, PRECISION), debtVal);
    }

    function _hasAnyDebt(address _user) internal view returns (bool) {
        for (uint256 i = 1; i <= reserveCount; i++) {
            if (IVybssDebtToken(reserveStates[i].debtTokenAddress).balanceOf(_user) > 0) {
                return true;
            }
        }
        return false;
    }

    // ═══════════════════════════════════════════════════════════
    //               INTERNAL - COLLATERAL BITMAP
    // ═══════════════════════════════════════════════════════════

    function _setCollateral(address _user, uint256 _reserveId, bool _enabled) internal {
        if (_enabled) {
            userConfigs[_user].collateralBitmap |= (1 << _reserveId);
        } else {
            userConfigs[_user].collateralBitmap &= ~(1 << _reserveId);
        }
    }

    function _isCollateral(address _user, uint256 _reserveId) internal view returns (bool) {
        return (userConfigs[_user].collateralBitmap & (1 << _reserveId)) != 0;
    }
}

/// @notice Interface for flash loan receivers.
///         Contracts that wish to use flash loans must implement this interface.
///         The executeOperation callback is called by the pool after transferring
///         the requested amount. The receiver must repay amount + premium to the
///         pool before returning, and must return true to signal success.
interface IFlashLoanReceiver {
    /// @param asset The address of the borrowed token
    /// @param amount The amount of tokens borrowed
    /// @param premium The fee to be paid on top of the borrowed amount
    /// @param initiator The address that initiated the flash loan (msg.sender of flashLoan)
    /// @param params Arbitrary data passed through from the flash loan caller
    /// @return True if the operation was successful and repayment was made
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}
