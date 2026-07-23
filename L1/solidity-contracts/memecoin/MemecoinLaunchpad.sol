// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Meme {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title MemecoinLaunchpad — Pump.fun-style bonding curve on Quantos
/// @notice Virtual-AMM (constant product) bonding curve. 0.5 % trade fee → creator.
///         Migration to DEX when QTEST raised ≥ target.
///
/// Tokenomics per memecoin (1 B total supply):
///   80 %  bonding curve   (800 M)
///   10 %  creator vesting (100 M) — 1 yr cliff then 5 %/month
///    5 %  DEX liquidity   ( 50 M) — released at migration
///    5 %  platform        ( 50 M) — sent to Vybss wallet immediately
contract MemecoinLaunchpad {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }
    function _add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function _sub(uint256 a, uint256 b) internal pure returns (uint256) { return a - b; }

    // ── Constants ───────────────────────────────────────────────
    uint256 public constant TOTAL_SUPPLY       = 1000000000000000000000000000; // 1B * 1e18
    uint256 public constant CURVE_ALLOC        =  800000000000000000000000000; // 80 %
    uint256 public constant CREATOR_ALLOC      =  100000000000000000000000000; // 10 %
    uint256 public constant DEX_ALLOC          =   50000000000000000000000000; //  5 %
    uint256 public constant PLATFORM_ALLOC     =   50000000000000000000000000; //  5 %

    uint256 public constant TRADE_FEE_BPS      = 50;   // 0.5 %
    uint256 public constant BPS_DENOM          = 10000;

    uint256 public constant MIGRATION_TARGET   = 50000000000000000000000; // 50,000 QTEST

    uint256 public constant INITIAL_VIRTUAL_QTEST = 30000000000000000000; // 30 QTEST virtual (testing)

    uint256 public constant VESTING_CLIFF      = 31536000; // 365 days in seconds
    uint256 public constant VESTING_MONTH      = 2592000;  // 30 days in seconds
    uint256 public constant VESTING_PCT_MONTH  = 5;        // 5 % per month (20 months full)

    // ── State ───────────────────────────────────────────────────
    address public paymentToken;   // QTEST
    address public platformWallet; // Vybss wallet
    address public owner;

    struct TokenInfo {
        address tokenAddress;
        address creator;
        uint256 virtualQtestReserve;   // includes virtual 15000 QTEST
        uint256 tokenReserve;          // tokens remaining in curve
        uint256 kProduct;              // constant product X * Y
        uint256 qtestCollected;        // real QTEST held by contract for this token
        uint256 creatorAlloc;          // locked creator tokens
        uint256 creatorVested;         // already claimed
        uint256 dexAlloc;              // locked for DEX migration
        uint256 createdAt;
        bool    migrated;
    }

    mapping(uint256 => TokenInfo) private _tokens;
    uint256 private _nextTokenId;

    // ── Events ──────────────────────────────────────────────────
    event TokenCreated(uint256 indexed tokenId, address token, address creator);
    event TokensBought(uint256 indexed tokenId, address buyer, uint256 qtestIn, uint256 tokensOut, uint256 newPrice);
    event TokensSold(uint256 indexed tokenId, address seller, uint256 tokensIn, uint256 qtestOut, uint256 newPrice);
    event Migrated(uint256 indexed tokenId, uint256 qtestAmount, uint256 tokenAmount);
    event CreatorClaimed(uint256 indexed tokenId, address creator, uint256 amount);

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _paymentToken, address _platformWallet) {
        paymentToken   = _paymentToken;
        platformWallet = _platformWallet;
        owner          = msg.sender;
    }

    // ══════════════════════════════════════════════════════════════
    //  CREATE TOKEN
    // ══════════════════════════════════════════════════════════════

    /// @notice Register a freshly-deployed MemecoinToken whose 1B supply sits in this contract.
    /// @param _tokenAddress  Address of the deployed ERC20
    /// @param _creator       Wallet that receives fee + vesting
    function createToken(address _tokenAddress, address _creator) external returns (uint256) {
        // The token must have minted TOTAL_SUPPLY to this contract already
        uint256 bal = IERC20Meme(_tokenAddress).balanceOf(address(this));
        require(bal >= TOTAL_SUPPLY, "token balance too low");

        uint256 tokenId = _nextTokenId;
        _nextTokenId = _add(tokenId, 1);

        // Send 5% platform allocation to Vybss wallet immediately
        require(
            IERC20Meme(_tokenAddress).transfer(platformWallet, PLATFORM_ALLOC),
            "platform transfer failed"
        );

        // Initialise bonding curve (constant product)
        uint256 k = _mul(INITIAL_VIRTUAL_QTEST, CURVE_ALLOC);

        _tokens[tokenId] = TokenInfo({
            tokenAddress:        _tokenAddress,
            creator:             _creator,
            virtualQtestReserve: INITIAL_VIRTUAL_QTEST,
            tokenReserve:        CURVE_ALLOC,
            kProduct:            k,
            qtestCollected:      0,
            creatorAlloc:        CREATOR_ALLOC,
            creatorVested:       0,
            dexAlloc:            DEX_ALLOC,
            createdAt:           block.timestamp,
            migrated:            false
        });

        emit TokenCreated(tokenId, _tokenAddress, _creator);
        return tokenId;
    }

    // ══════════════════════════════════════════════════════════════
    //  BUY — QTEST → Memecoin tokens
    // ══════════════════════════════════════════════════════════════

    function buyTokens(uint256 _tokenId, uint256 _qtestAmount) external returns (uint256) {
        TokenInfo storage t = _tokens[_tokenId];
        require(t.tokenAddress != address(0), "token not found");
        require(!t.migrated, "already migrated to DEX");
        require(_qtestAmount > 0, "amount must be > 0");

        // Pull QTEST from buyer
        require(
            IERC20Meme(paymentToken).transferFrom(msg.sender, address(this), _qtestAmount),
            "QTEST transfer failed"
        );

        // 0.5 % fee → creator
        uint256 fee       = _div(_mul(_qtestAmount, TRADE_FEE_BPS), BPS_DENOM);
        uint256 netAmount = _sub(_qtestAmount, fee);

        if (fee > 0) {
            require(
                IERC20Meme(paymentToken).transfer(t.creator, fee),
                "fee transfer failed"
            );
        }

        // Constant product: dy = Y - K / (X + dx)
        uint256 newX      = _add(t.virtualQtestReserve, netAmount);
        uint256 newY      = _div(t.kProduct, newX);
        uint256 tokensOut  = _sub(t.tokenReserve, newY);

        require(tokensOut > 0, "insufficient output");
        require(tokensOut <= t.tokenReserve, "not enough tokens in curve");

        // Update state
        t.virtualQtestReserve = newX;
        t.tokenReserve        = newY;
        t.qtestCollected      = _add(t.qtestCollected, netAmount);

        // Send tokens to buyer
        require(
            IERC20Meme(t.tokenAddress).transfer(msg.sender, tokensOut),
            "token transfer failed"
        );

        // Spot price for event (X / Y scaled by 1e18)
        uint256 spotPrice = _div(_mul(newX, 1000000000000000000), newY);

        emit TokensBought(_tokenId, msg.sender, _qtestAmount, tokensOut, spotPrice);

        // Auto-migrate if target reached
        if (t.qtestCollected >= MIGRATION_TARGET && !t.migrated) {
            _doMigrate(_tokenId);
        }

        return tokensOut;
    }

    // ══════════════════════════════════════════════════════════════
    //  SELL — Memecoin tokens → QTEST
    // ══════════════════════════════════════════════════════════════

    function sellTokens(uint256 _tokenId, uint256 _tokenAmount) external returns (uint256) {
        TokenInfo storage t = _tokens[_tokenId];
        require(t.tokenAddress != address(0), "token not found");
        require(!t.migrated, "already migrated to DEX");
        require(_tokenAmount > 0, "amount must be > 0");

        // Pull tokens from seller
        require(
            IERC20Meme(t.tokenAddress).transferFrom(msg.sender, address(this), _tokenAmount),
            "token transfer failed"
        );

        // Constant product: dx = X - K / (Y + dy)
        uint256 newY      = _add(t.tokenReserve, _tokenAmount);
        uint256 newX      = _div(t.kProduct, newY);
        uint256 grossQtest = _sub(t.virtualQtestReserve, newX);

        require(grossQtest > 0, "insufficient output");
        require(grossQtest <= t.qtestCollected, "not enough QTEST in reserve");

        // 0.5 % fee → creator
        uint256 fee       = _div(_mul(grossQtest, TRADE_FEE_BPS), BPS_DENOM);
        uint256 netPayout = _sub(grossQtest, fee);

        // Update state
        t.virtualQtestReserve = newX;
        t.tokenReserve        = newY;
        t.qtestCollected      = _sub(t.qtestCollected, grossQtest);

        // Pay seller
        require(
            IERC20Meme(paymentToken).transfer(msg.sender, netPayout),
            "QTEST payout failed"
        );

        // Pay creator fee
        if (fee > 0) {
            require(
                IERC20Meme(paymentToken).transfer(t.creator, fee),
                "fee transfer failed"
            );
        }

        uint256 spotPrice = 0;
        if (newY > 0) {
            spotPrice = _div(_mul(newX, 1000000000000000000), newY);
        }

        emit TokensSold(_tokenId, msg.sender, _tokenAmount, netPayout, spotPrice);
        return netPayout;
    }

    // ══════════════════════════════════════════════════════════════
    //  MIGRATION → DEX
    // ══════════════════════════════════════════════════════════════

    /// @notice Triggers migration after target reached. Flags token as migrated.
    ///         Funds stay in contract until claimMigrationFunds() is called.
    function migrate(uint256 _tokenId) external {
        TokenInfo storage t = _tokens[_tokenId];
        require(t.tokenAddress != address(0), "token not found");
        require(!t.migrated, "already migrated");
        require(t.qtestCollected >= MIGRATION_TARGET, "target not reached");
        _doMigrate(_tokenId);
    }

    function _doMigrate(uint256 _tokenId) internal {
        TokenInfo storage t = _tokens[_tokenId];
        t.migrated = true;
        // Funds (dexAlloc tokens + qtestCollected) stay in the contract
        // until claimMigrationFunds() releases them to the caller for pool creation.
        emit Migrated(_tokenId, t.qtestCollected, t.dexAlloc);
    }

    /// @notice Anyone can claim migration funds to create the DEX pool.
    ///         Sends DEX token allocation + collected QTEST to msg.sender.
    function claimMigrationFunds(uint256 _tokenId) external returns (uint256 qtestAmount, uint256 tokenAmount) {
        TokenInfo storage t = _tokens[_tokenId];
        require(t.migrated, "not migrated yet");
        require(t.dexAlloc > 0 || t.qtestCollected > 0, "already claimed");

        tokenAmount = t.dexAlloc;
        qtestAmount = t.qtestCollected;

        if (tokenAmount > 0) {
            t.dexAlloc = 0;
            require(
                IERC20Meme(t.tokenAddress).transfer(msg.sender, tokenAmount),
                "DEX token transfer failed"
            );
        }

        if (qtestAmount > 0) {
            t.qtestCollected = 0;
            require(
                IERC20Meme(paymentToken).transfer(msg.sender, qtestAmount),
                "DEX QTEST transfer failed"
            );
        }

        return (qtestAmount, tokenAmount);
    }

    // ══════════════════════════════════════════════════════════════
    //  CREATOR VESTING — 1 yr cliff then 5 %/month
    // ══════════════════════════════════════════════════════════════

    function claimCreatorTokens(uint256 _tokenId) external {
        TokenInfo storage t = _tokens[_tokenId];
        require(msg.sender == t.creator, "not creator");
        require(block.timestamp >= _add(t.createdAt, VESTING_CLIFF), "cliff not reached");

        uint256 elapsed      = _sub(block.timestamp, _add(t.createdAt, VESTING_CLIFF));
        uint256 monthsPassed = _div(elapsed, VESTING_MONTH);
        // 5 % per month → 20 months max
        uint256 vestPct      = _mul(monthsPassed, VESTING_PCT_MONTH);
        if (vestPct > 100) { vestPct = 100; }

        uint256 totalVestable = _div(_mul(CREATOR_ALLOC, vestPct), 100);
        uint256 claimable     = _sub(totalVestable, t.creatorVested);
        require(claimable > 0, "nothing to claim");

        t.creatorVested = _add(t.creatorVested, claimable);
        t.creatorAlloc  = _sub(t.creatorAlloc,  claimable);

        require(
            IERC20Meme(t.tokenAddress).transfer(t.creator, claimable),
            "vesting transfer failed"
        );

        emit CreatorClaimed(_tokenId, t.creator, claimable);
    }

    // ══════════════════════════════════════════════════════════════
    //  VIEW FUNCTIONS
    // ══════════════════════════════════════════════════════════════

    function nextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    /// @notice Returns curve state for a token
    function getTokenInfo(uint256 _tokenId) external view returns (
        address tokenAddress,
        address creator,
        uint256 virtualQtestReserve,
        uint256 tokenReserve,
        uint256 qtestCollected,
        uint256 creatorAlloc,
        bool    migrated
    ) {
        TokenInfo storage t = _tokens[_tokenId];
        return (
            t.tokenAddress,
            t.creator,
            t.virtualQtestReserve,
            t.tokenReserve,
            t.qtestCollected,
            t.creatorAlloc,
            t.migrated
        );
    }

    /// @notice Quote: how many tokens for `_qtestAmount` QTEST?
    function getPrice(uint256 _tokenId, uint256 _qtestAmount) external view returns (uint256) {
        TokenInfo storage t = _tokens[_tokenId];
        if (t.migrated || t.tokenAddress == address(0)) return 0;
        uint256 fee       = _div(_mul(_qtestAmount, TRADE_FEE_BPS), BPS_DENOM);
        uint256 netAmount = _sub(_qtestAmount, fee);
        uint256 newX      = _add(t.virtualQtestReserve, netAmount);
        uint256 newY      = _div(t.kProduct, newX);
        return _sub(t.tokenReserve, newY);
    }

    /// @notice Quote: how much QTEST for selling `_tokenAmount` tokens?
    function getSellQuote(uint256 _tokenId, uint256 _tokenAmount) external view returns (uint256) {
        TokenInfo storage t = _tokens[_tokenId];
        if (t.migrated || t.tokenAddress == address(0)) return 0;
        uint256 newY       = _add(t.tokenReserve, _tokenAmount);
        uint256 newX       = _div(t.kProduct, newY);
        uint256 grossQtest = _sub(t.virtualQtestReserve, newX);
        uint256 fee        = _div(_mul(grossQtest, TRADE_FEE_BPS), BPS_DENOM);
        return _sub(grossQtest, fee);
    }

    // ── Admin ───────────────────────────────────────────────────

    function setPlatformWallet(address _newWallet) external {
        require(msg.sender == owner, "not owner");
        platformWallet = _newWallet;
    }

    function transferOwnership(address _newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = _newOwner;
    }
}
