// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title PriceOracle - On-chain price feed storage for Quantos derivatives
/// @notice Stores prices pushed by the off-chain Pyth relayer (Dilithium-3 signed)
/// @dev Prices are keyed by Pyth feed ID (bytes32). Only the authorized relayer can update.
contract PriceOracle {
    address public owner;
    address public relayer;

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    struct PriceData {
        int64  price;        // Price in base units
        uint64 conf;         // Confidence interval
        int32  expo;         // Exponent (e.g. -8 means price * 10^-8)
        uint64 publishTime;  // Unix timestamp of the price update
        int64  emaPrice;     // Exponential moving average price
        uint64 emaConf;      // EMA confidence
    }

    // feedId (bytes32) => PriceData
    mapping(bytes32 => PriceData) public prices;

    // Track all registered feed IDs
    bytes32[] public feedIds;
    mapping(bytes32 => bool) public feedRegistered;

    event PriceUpdated(bytes32 indexed feedId, int64 price, int32 expo, uint64 publishTime);
    event BatchPriceUpdated(uint256 count, uint64 publishTime);
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);
    event FeedRegistered(bytes32 indexed feedId);

    constructor() {
        owner = msg.sender;
        relayer = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer || msg.sender == owner, "Only relayer");
        _;
    }

    // ── Admin functions ─────────────────────────────────────────

    function setRelayer(address _relayer) external onlyOwner {
        require(_relayer != address(0), "Invalid relayer");
        address old = relayer;
        relayer = _relayer;
        emit RelayerUpdated(old, _relayer);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    function registerFeed(bytes32 feedId) external onlyOwner {
        require(!feedRegistered[feedId], "Already registered");
        feedRegistered[feedId] = true;
        feedIds.push(feedId);
        emit FeedRegistered(feedId);
    }

    // ── Price update functions ──────────────────────────────────

    /// @notice Update a single price feed
    function updatePrice(
        bytes32 feedId,
        int64   price,
        uint64  conf,
        int32   expo,
        uint64  publishTime,
        int64   emaPrice,
        uint64  emaConf
    ) external onlyRelayer {
        // Only accept if newer than existing
        require(publishTime >= prices[feedId].publishTime, "Stale price");

        prices[feedId] = PriceData({
            price:       price,
            conf:        conf,
            expo:        expo,
            publishTime: publishTime,
            emaPrice:    emaPrice,
            emaConf:     emaConf
        });

        // Auto-register if not already
        if (!feedRegistered[feedId]) {
            feedRegistered[feedId] = true;
            feedIds.push(feedId);
        }

        emit PriceUpdated(feedId, price, expo, publishTime);
    }

    /// @notice Batch update multiple price feeds in a single tx
    /// @dev More gas-efficient for the relayer when updating many feeds
    function batchUpdatePrices(
        bytes32[] calldata _feedIds,
        int64[]   calldata _prices,
        uint64[]  calldata _confs,
        int32[]   calldata _expos,
        uint64[]  calldata _publishTimes,
        int64[]   calldata _emaPrices,
        uint64[]  calldata _emaConfs
    ) external onlyRelayer {
        uint256 len = _feedIds.length;
        require(
            len == _prices.length &&
            len == _confs.length &&
            len == _expos.length &&
            len == _publishTimes.length &&
            len == _emaPrices.length &&
            len == _emaConfs.length,
            "Array length mismatch"
        );

        uint64 batchTime = 0;
        for (uint256 i = 0; i < len; i++) {
            bytes32 fid = _feedIds[i];

            // Skip stale prices
            if (_publishTimes[i] < prices[fid].publishTime) continue;

            prices[fid] = PriceData({
                price:       _prices[i],
                conf:        _confs[i],
                expo:        _expos[i],
                publishTime: _publishTimes[i],
                emaPrice:    _emaPrices[i],
                emaConf:     _emaConfs[i]
            });

            if (!feedRegistered[fid]) {
                feedRegistered[fid] = true;
                feedIds.push(fid);
            }

            if (_publishTimes[i] > batchTime) batchTime = _publishTimes[i];
        }

        emit BatchPriceUpdated(len, batchTime);
    }

    // ── Read functions ──────────────────────────────────────────

    /// @notice Get the latest price for a feed
    function getPrice(bytes32 feedId) external view returns (
        int64 price, uint64 conf, int32 expo, uint64 publishTime
    ) {
        PriceData storage pd = prices[feedId];
        return (pd.price, pd.conf, pd.expo, pd.publishTime);
    }

    /// @notice Get the full price data including EMA
    function getPriceData(bytes32 feedId) external view returns (PriceData memory) {
        return prices[feedId];
    }

    /// @notice Get the normalized price (scaled to 18 decimals)
    function getNormalizedPrice(bytes32 feedId) external view returns (uint256) {
        PriceData storage pd = prices[feedId];
        require(pd.publishTime > 0, "No price data");
        require(pd.price > 0, "Invalid price");

        uint256 absPrice = uint256(uint64(pd.price));

        if (pd.expo >= 0) {
            return _mul(absPrice, 10 ** (18 + uint32(pd.expo)));
        } else {
            uint32 absExpo = uint32(-pd.expo);
            if (absExpo <= 18) {
                return _mul(absPrice, 10 ** (18 - absExpo));
            } else {
                return _div(absPrice, 10 ** (absExpo - 18));
            }
        }
    }

    /// @notice Check if a price is fresh (within maxAge seconds)
    function isPriceFresh(bytes32 feedId, uint64 maxAge) external view returns (bool) {
        return (block.timestamp - prices[feedId].publishTime) <= maxAge;
    }

    /// @notice Get total number of registered feeds
    function getFeedCount() external view returns (uint256) {
        return feedIds.length;
    }
}
