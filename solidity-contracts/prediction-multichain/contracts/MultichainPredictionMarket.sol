// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MultichainPredictionMarket is Ownable {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_OUTCOMES = 8;
    uint256 public constant TOTAL_FEE_BPS = 200;
    uint256 public constant PROTOCOL_FEE_BPS = 50;
    uint256 public constant LP_FEE_BPS = 150;
    uint256 public constant BPS = 10_000;
    uint256 private constant ACC_PRECISION = 1e18;

    enum MarketStatus {
        Trading,
        Resolved
    }

    struct Market {
        address creator;
        address collateralToken;
        address resolver;
        uint40 tradingEndsAt;
        uint8 numOutcomes;
        MarketStatus status;
        uint8 winningOutcome;
        uint256 totalLiquidityShares;
        uint256 accLpFeePerShare;
        uint256 lpFeeVault;
        uint256 backstopCollateral;
        uint256 lockedWinningCollateral;
        uint256 redeemableLiquidity;
        uint256[8] pools;
        uint256[8] totalOutcomeShares;
    }

    struct LPPosition {
        uint256 liquidityShares;
        uint256 feeDebt;
        uint256 claimableFees;
    }

    address public protocolFeeRecipient;
    uint256 public nextMarketId;

    mapping(uint256 => Market) public markets;
    mapping(uint256 => mapping(address => uint256[8])) public userShares;
    mapping(uint256 => mapping(address => LPPosition)) public lpPositions;

    event ProtocolFeeRecipientUpdated(address indexed previousRecipient, address indexed newRecipient);
    event MarketCreated(uint256 indexed marketId, address indexed creator, address indexed collateralToken, uint8 numOutcomes, uint256 initialLiquidity, uint256 tradingEndsAt, address resolver);
    event LiquidityAdded(uint256 indexed marketId, address indexed provider, uint256 collateralAmount, uint256 mintedShares);
    event LiquidityRedeemed(uint256 indexed marketId, address indexed provider, uint256 collateralAmount, uint256 burnedShares);
    event SharesBought(uint256 indexed marketId, address indexed buyer, uint8 indexed outcomeIndex, uint256 collateralIn, uint256 sharesOut, uint256 protocolFee, uint256 lpFee);
    event SharesSold(uint256 indexed marketId, address indexed seller, uint8 indexed outcomeIndex, uint256 sharesIn, uint256 collateralOut, uint256 protocolFee, uint256 lpFee);
    event MarketResolved(uint256 indexed marketId, uint8 indexed winningOutcome, uint256 lockedWinningCollateral, uint256 redeemableLiquidity);
    event WinningsClaimed(uint256 indexed marketId, address indexed user, uint256 collateralOut);
    event LpFeesClaimed(uint256 indexed marketId, address indexed provider, uint256 collateralOut);

    error InvalidRecipient();
    error InvalidOutcomeCount();
    error InvalidOutcome();
    error InvalidResolver();
    error InvalidAmount();
    error InvalidTimestamp();
    error MarketNotTrading();
    error MarketNotResolved();
    error MarketStillTrading();
    error MarketClosed();
    error NotResolver();
    error NotEnoughShares();
    error ZeroSharesOut();
    error ZeroPayout();
    error InsufficientBackstop();
    error NoClaimableFees();
    error NoLiquidity();
    error NoWinnings();

    constructor(address initialOwner, address protocolFeeRecipient_) Ownable(initialOwner) {
        if (protocolFeeRecipient_ == address(0)) revert InvalidRecipient();
        protocolFeeRecipient = protocolFeeRecipient_;
    }

    function setProtocolFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert InvalidRecipient();
        emit ProtocolFeeRecipientUpdated(protocolFeeRecipient, newRecipient);
        protocolFeeRecipient = newRecipient;
    }

    function createMarket(
        address collateralToken,
        uint8 numOutcomes,
        uint256 tradingEndsAt,
        uint256 initialLiquidity,
        address resolver
    ) external returns (uint256 marketId) {
        if (collateralToken == address(0)) revert InvalidRecipient();
        if (resolver == address(0)) revert InvalidResolver();
        if (numOutcomes < 2 || numOutcomes > MAX_OUTCOMES) revert InvalidOutcomeCount();
        if (tradingEndsAt <= block.timestamp) revert InvalidTimestamp();
        if (initialLiquidity == 0) revert InvalidAmount();

        IERC20(collateralToken).safeTransferFrom(msg.sender, address(this), initialLiquidity);

        marketId = nextMarketId++;
        Market storage market = markets[marketId];
        market.creator = msg.sender;
        market.collateralToken = collateralToken;
        market.resolver = resolver;
        market.tradingEndsAt = uint40(tradingEndsAt);
        market.numOutcomes = numOutcomes;
        market.status = MarketStatus.Trading;
        market.totalLiquidityShares = initialLiquidity;
        market.backstopCollateral = initialLiquidity;

        _allocateAcrossPools(market, initialLiquidity);
        _creditLiquidity(marketId, msg.sender, initialLiquidity);

        emit MarketCreated(marketId, msg.sender, collateralToken, numOutcomes, initialLiquidity, tradingEndsAt, resolver);
        emit LiquidityAdded(marketId, msg.sender, initialLiquidity, initialLiquidity);
    }

    function addLiquidity(uint256 marketId, uint256 collateralAmount) external {
        Market storage market = markets[marketId];
        _requireTrading(market);
        if (collateralAmount == 0) revert InvalidAmount();

        _syncLpPosition(marketId, msg.sender);

        uint256 mintedShares;
        if (market.totalLiquidityShares == 0 || market.backstopCollateral == 0) {
            mintedShares = collateralAmount;
        } else {
            mintedShares = collateralAmount * market.totalLiquidityShares / market.backstopCollateral;
        }
        if (mintedShares == 0) revert NoLiquidity();

        IERC20(market.collateralToken).safeTransferFrom(msg.sender, address(this), collateralAmount);

        market.totalLiquidityShares += mintedShares;
        market.backstopCollateral += collateralAmount;
        _allocateAcrossPools(market, collateralAmount);
        _creditLiquidity(marketId, msg.sender, mintedShares);

        emit LiquidityAdded(marketId, msg.sender, collateralAmount, mintedShares);
    }

    function buyShares(uint256 marketId, uint8 outcomeIndex, uint256 collateralAmount) external {
        Market storage market = markets[marketId];
        _requireTrading(market);
        if (outcomeIndex >= market.numOutcomes) revert InvalidOutcome();
        if (collateralAmount == 0) revert InvalidAmount();

        IERC20 token = IERC20(market.collateralToken);
        token.safeTransferFrom(msg.sender, address(this), collateralAmount);

        uint256 protocolFee = collateralAmount * PROTOCOL_FEE_BPS / BPS;
        uint256 lpFee = collateralAmount * LP_FEE_BPS / BPS;
        uint256 netCollateral = collateralAmount - protocolFee - lpFee;

        if (protocolFee > 0) {
            token.safeTransfer(protocolFeeRecipient, protocolFee);
        }
        _accrueLpFee(marketId, lpFee);
        market.backstopCollateral += netCollateral;

        uint256 sharesOut = _calcBuyShares(market, outcomeIndex, netCollateral);
        if (sharesOut == 0) revert ZeroSharesOut();

        for (uint8 i = 0; i < market.numOutcomes; i++) {
            market.pools[i] += netCollateral;
        }
        market.pools[outcomeIndex] -= sharesOut;

        userShares[marketId][msg.sender][outcomeIndex] += sharesOut;
        market.totalOutcomeShares[outcomeIndex] += sharesOut;

        emit SharesBought(marketId, msg.sender, outcomeIndex, collateralAmount, sharesOut, protocolFee, lpFee);
    }

    function sellShares(uint256 marketId, uint8 outcomeIndex, uint256 sharesIn) external {
        Market storage market = markets[marketId];
        _requireTrading(market);
        if (outcomeIndex >= market.numOutcomes) revert InvalidOutcome();
        if (sharesIn == 0) revert InvalidAmount();
        if (userShares[marketId][msg.sender][outcomeIndex] < sharesIn) revert NotEnoughShares();

        uint256 payoutGross = _calcSellPayout(market, outcomeIndex, sharesIn);
        if (payoutGross == 0) revert ZeroPayout();
        if (market.backstopCollateral < payoutGross) revert InsufficientBackstop();

        uint256 protocolFee = payoutGross * PROTOCOL_FEE_BPS / BPS;
        uint256 lpFee = payoutGross * LP_FEE_BPS / BPS;
        uint256 sellerPayout = payoutGross - protocolFee - lpFee;

        market.pools[outcomeIndex] += sharesIn;
        uint256 perPoolReduction = payoutGross / market.numOutcomes;
        for (uint8 i = 0; i < market.numOutcomes; i++) {
            market.pools[i] -= perPoolReduction;
        }

        market.backstopCollateral -= payoutGross;
        userShares[marketId][msg.sender][outcomeIndex] -= sharesIn;
        market.totalOutcomeShares[outcomeIndex] -= sharesIn;

        IERC20 token = IERC20(market.collateralToken);
        if (protocolFee > 0) {
            token.safeTransfer(protocolFeeRecipient, protocolFee);
        }
        _accrueLpFee(marketId, lpFee);
        token.safeTransfer(msg.sender, sellerPayout);

        emit SharesSold(marketId, msg.sender, outcomeIndex, sharesIn, sellerPayout, protocolFee, lpFee);
    }

    function resolveMarket(uint256 marketId, uint8 winningOutcome) external {
        Market storage market = markets[marketId];
        if (market.status != MarketStatus.Trading) revert MarketNotTrading();
        if (block.timestamp < market.tradingEndsAt) revert MarketStillTrading();
        if (winningOutcome >= market.numOutcomes) revert InvalidOutcome();
        if (msg.sender != market.resolver && msg.sender != owner()) revert NotResolver();

        uint256 lockedWinningCollateral = market.totalOutcomeShares[winningOutcome];
        if (market.backstopCollateral < lockedWinningCollateral) revert InsufficientBackstop();

        market.status = MarketStatus.Resolved;
        market.winningOutcome = winningOutcome;
        market.lockedWinningCollateral = lockedWinningCollateral;
        market.redeemableLiquidity = market.backstopCollateral - lockedWinningCollateral;

        emit MarketResolved(marketId, winningOutcome, lockedWinningCollateral, market.redeemableLiquidity);
    }

    function claimWinnings(uint256 marketId) external {
        Market storage market = markets[marketId];
        if (market.status != MarketStatus.Resolved) revert MarketNotResolved();

        uint8 winningOutcome = market.winningOutcome;
        uint256 winningShares = userShares[marketId][msg.sender][winningOutcome];
        if (winningShares == 0) revert NoWinnings();

        userShares[marketId][msg.sender][winningOutcome] = 0;
        market.lockedWinningCollateral -= winningShares;
        market.backstopCollateral -= winningShares;

        IERC20(market.collateralToken).safeTransfer(msg.sender, winningShares);
        emit WinningsClaimed(marketId, msg.sender, winningShares);
    }

    function claimLpFees(uint256 marketId) external {
        Market storage market = markets[marketId];
        _syncLpPosition(marketId, msg.sender);

        LPPosition storage position = lpPositions[marketId][msg.sender];
        uint256 claimable = position.claimableFees;
        if (claimable == 0) revert NoClaimableFees();

        position.claimableFees = 0;
        position.feeDebt = position.liquidityShares * market.accLpFeePerShare / ACC_PRECISION;
        market.lpFeeVault -= claimable;

        IERC20(market.collateralToken).safeTransfer(msg.sender, claimable);
        emit LpFeesClaimed(marketId, msg.sender, claimable);
    }

    function redeemLiquidity(uint256 marketId, uint256 liquiditySharesToBurn) external {
        Market storage market = markets[marketId];
        if (market.status != MarketStatus.Resolved) revert MarketNotResolved();
        if (liquiditySharesToBurn == 0) revert InvalidAmount();

        _syncLpPosition(marketId, msg.sender);

        LPPosition storage position = lpPositions[marketId][msg.sender];
        if (position.liquidityShares < liquiditySharesToBurn) revert NoLiquidity();

        uint256 collateralOut = market.redeemableLiquidity * liquiditySharesToBurn / market.totalLiquidityShares;
        if (collateralOut == 0) revert NoLiquidity();

        position.liquidityShares -= liquiditySharesToBurn;
        position.feeDebt = position.liquidityShares * market.accLpFeePerShare / ACC_PRECISION;
        market.totalLiquidityShares -= liquiditySharesToBurn;
        market.redeemableLiquidity -= collateralOut;
        market.backstopCollateral -= collateralOut;

        IERC20(market.collateralToken).safeTransfer(msg.sender, collateralOut);
        emit LiquidityRedeemed(marketId, msg.sender, collateralOut, liquiditySharesToBurn);
    }

    function getOutcomePrice(uint256 marketId, uint8 outcomeIndex) external view returns (uint256 priceE18) {
        Market storage market = markets[marketId];
        if (outcomeIndex >= market.numOutcomes) revert InvalidOutcome();

        uint256 scale = 1e36;
        uint256 reciprocalSum;
        for (uint8 i = 0; i < market.numOutcomes; i++) {
            uint256 pool = market.pools[i];
            if (pool == 0) return 0;
            reciprocalSum += scale / pool;
        }
        if (reciprocalSum == 0) return 0;

        return (scale / market.pools[outcomeIndex]) * 1e18 / reciprocalSum;
    }

    function getPools(uint256 marketId) external view returns (uint256[8] memory) {
        return markets[marketId].pools;
    }

    function getUserShares(uint256 marketId, address user) external view returns (uint256[8] memory) {
        return userShares[marketId][user];
    }

    function getLpPosition(uint256 marketId, address provider) external view returns (uint256 liquidityShares, uint256 pendingFees, uint256 feeDebt) {
        Market storage market = markets[marketId];
        LPPosition storage position = lpPositions[marketId][provider];
        uint256 accrued = position.liquidityShares * market.accLpFeePerShare / ACC_PRECISION;
        uint256 extra = accrued > position.feeDebt ? accrued - position.feeDebt : 0;
        return (position.liquidityShares, position.claimableFees + extra, position.feeDebt);
    }

    function _creditLiquidity(uint256 marketId, address provider, uint256 mintedShares) internal {
        LPPosition storage position = lpPositions[marketId][provider];
        position.liquidityShares += mintedShares;
        position.feeDebt = position.liquidityShares * markets[marketId].accLpFeePerShare / ACC_PRECISION;
    }

    function _syncLpPosition(uint256 marketId, address provider) internal {
        Market storage market = markets[marketId];
        LPPosition storage position = lpPositions[marketId][provider];

        if (position.liquidityShares == 0) {
            position.feeDebt = 0;
            return;
        }

        uint256 accrued = position.liquidityShares * market.accLpFeePerShare / ACC_PRECISION;
        if (accrued > position.feeDebt) {
            position.claimableFees += accrued - position.feeDebt;
        }
        position.feeDebt = accrued;
    }

    function _accrueLpFee(uint256 marketId, uint256 lpFee) internal {
        if (lpFee == 0) return;
        Market storage market = markets[marketId];
        market.lpFeeVault += lpFee;
        if (market.totalLiquidityShares > 0) {
            market.accLpFeePerShare += lpFee * ACC_PRECISION / market.totalLiquidityShares;
        }
    }

    function _requireTrading(Market storage market) internal view {
        if (market.status != MarketStatus.Trading) revert MarketNotTrading();
        if (block.timestamp >= market.tradingEndsAt) revert MarketClosed();
    }

    function _allocateAcrossPools(Market storage market, uint256 collateralAmount) internal {
        uint256 perOutcome = collateralAmount / market.numOutcomes;
        uint256 remainder = collateralAmount - (perOutcome * market.numOutcomes);

        for (uint8 i = 0; i < market.numOutcomes; i++) {
            market.pools[i] += perOutcome;
        }
        if (remainder > 0) {
            market.pools[0] += remainder;
        }
    }

    function _calcBuyShares(Market storage market, uint8 targetOutcome, uint256 amount) internal view returns (uint256) {
        uint256 ratio = market.pools[targetOutcome];
        for (uint8 i = 0; i < market.numOutcomes; i++) {
            if (i == targetOutcome) continue;
            ratio = ratio * market.pools[i] / (market.pools[i] + amount);
        }
        return (market.pools[targetOutcome] + amount) - ratio;
    }

    function _calcSellPayout(Market storage market, uint8 targetOutcome, uint256 sharesIn) internal view returns (uint256) {
        uint256 scale = 1e36;
        uint256 reciprocalSum;
        for (uint8 i = 0; i < market.numOutcomes; i++) {
            uint256 pool = market.pools[i];
            if (pool == 0) return 0;
            reciprocalSum += scale / pool;
        }
        if (reciprocalSum == 0) return 0;

        uint256 price = ((scale / market.pools[targetOutcome]) * 1e18) / reciprocalSum;
        return sharesIn * price / 1e18;
    }
}
