// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Keys {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssProfileKeys — Social trading keys with bonding curve (Friend.tech style)
/// @notice Buy/sell keys of any creator. Price follows bonding curve: price = supply² * 1e8 / 16000.
///         5% creator royalty + 5% protocol fee on every trade.
contract VybssProfileKeys {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }
    function _add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function _sub(uint256 a, uint256 b) internal pure returns (uint256) { return a - b; }

    // ── Fee constants (basis points → %) ────────────────────────
    uint256 public constant CREATOR_FEE_PCT  = 5;   // 5%
    uint256 public constant PROTOCOL_FEE_PCT = 5;   // 5%
    uint256 public constant CURVE_DIVISOR    = 16000;
    uint256 public constant PRICE_SCALE      = 100000000; // 1e8 (QTEST decimals)

    // ── Token used for payment (QTEST) ──────────────────────────
    address public immutable paymentToken;

    // ── Protocol fee recipient ──────────────────────────────────
    address public protocolWallet;
    address public owner;

    // ── Storage ─────────────────────────────────────────────────
    /// supply[creator] → total keys in circulation for that creator
    mapping(address => uint256) public keySupply;
    /// balances[creator][holder] → number of keys held
    mapping(address => mapping(address => uint256)) public keyBalance;
    /// Accumulated creator earnings (from royalties) that can be claimed
    mapping(address => uint256) public creatorEarnings;
    /// Whether a creator has been registered (self-buy first key)
    mapping(address => bool) public isRegistered;

    // ── Trade counter for indexing ──────────────────────────────
    uint256 public nextTradeId;

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _paymentToken, address _protocolWallet) {
        paymentToken   = _paymentToken;
        protocolWallet = _protocolWallet;
        owner          = msg.sender;
    }

    // ── Price Calculation ───────────────────────────────────────
    /// @notice Get the price for buying `amount` keys starting from current supply
    ///         Uses integral of bonding curve: sum(i²) / DIVISOR
    function getBuyPrice(address _creator, uint256 _amount) public view returns (uint256) {
        uint256 supply = keySupply[_creator];
        return _getPriceForRange(supply, _amount);
    }

    /// @notice Get the price for selling `amount` keys starting from current supply
    function getSellPrice(address _creator, uint256 _amount) public view returns (uint256) {
        uint256 supply = keySupply[_creator];
        require(supply >= _amount, "not enough supply");
        return _getPriceForRange(_sub(supply, _amount), _amount);
    }

    /// @notice Get buy price including fees
    function getBuyPriceWithFees(address _creator, uint256 _amount) public view returns (uint256) {
        uint256 base = getBuyPrice(_creator, _amount);
        uint256 creatorFee  = _div(_mul(base, CREATOR_FEE_PCT), 100);
        uint256 protocolFee = _div(_mul(base, PROTOCOL_FEE_PCT), 100);
        return _add(_add(base, creatorFee), protocolFee);
    }

    /// @notice Get sell price after fees are deducted
    function getSellPriceAfterFees(address _creator, uint256 _amount) public view returns (uint256) {
        uint256 base = getSellPrice(_creator, _amount);
        uint256 creatorFee  = _div(_mul(base, CREATOR_FEE_PCT), 100);
        uint256 protocolFee = _div(_mul(base, PROTOCOL_FEE_PCT), 100);
        return _sub(_sub(base, creatorFee), protocolFee);
    }

    // ── Buy Keys ────────────────────────────────────────────────
    /// @notice Buy `_amount` keys of `_creator`. First buy by creator = registration.
    function buyKeys(address _creator, uint256 _amount) external returns (uint256) {
        require(_amount > 0, "amount must be > 0");

        uint256 supply = keySupply[_creator];

        // First key must be bought by the creator themselves (self-register)
        if (supply == 0) {
            require(msg.sender == _creator, "creator must buy first key");
            require(_amount == 1, "first buy must be 1 key");
            isRegistered[_creator] = true;
            // First key is free (price = 0² / 16000 = 0)
            keySupply[_creator]  = 1;
            keyBalance[_creator][_creator] = 1;
            uint256 tradeId = nextTradeId;
            nextTradeId = _add(tradeId, 1);
            return tradeId;
        }

        require(isRegistered[_creator], "creator not registered");

        uint256 basePrice   = _getPriceForRange(supply, _amount);
        uint256 creatorFee  = _div(_mul(basePrice, CREATOR_FEE_PCT), 100);
        uint256 protocolFee = _div(_mul(basePrice, PROTOCOL_FEE_PCT), 100);
        uint256 totalCost   = _add(_add(basePrice, creatorFee), protocolFee);

        // Transfer payment from buyer
        require(
            IERC20Keys(paymentToken).transferFrom(msg.sender, address(this), totalCost),
            "payment transfer failed"
        );

        // Distribute fees
        if (creatorFee > 0) {
            creatorEarnings[_creator] = _add(creatorEarnings[_creator], creatorFee);
        }
        if (protocolFee > 0) {
            require(
                IERC20Keys(paymentToken).transfer(protocolWallet, protocolFee),
                "protocol fee transfer failed"
            );
        }

        // Update balances
        keySupply[_creator]  = _add(supply, _amount);
        keyBalance[_creator][msg.sender] = _add(keyBalance[_creator][msg.sender], _amount);

        uint256 tradeId = nextTradeId;
        nextTradeId = _add(tradeId, 1);
        return tradeId;
    }

    // ── Sell Keys ───────────────────────────────────────────────
    /// @notice Sell `_amount` keys of `_creator` back to the curve
    function sellKeys(address _creator, uint256 _amount) external returns (uint256) {
        require(_amount > 0, "amount must be > 0");
        require(keyBalance[_creator][msg.sender] >= _amount, "not enough keys");

        uint256 supply = keySupply[_creator];
        require(supply > _amount, "cannot sell last key");

        // Creator can't sell their last key (stays registered)
        if (msg.sender == _creator) {
            require(
                _sub(keyBalance[_creator][msg.sender], _amount) >= 1,
                "creator must keep 1 key"
            );
        }

        uint256 basePrice   = _getPriceForRange(_sub(supply, _amount), _amount);
        uint256 creatorFee  = _div(_mul(basePrice, CREATOR_FEE_PCT), 100);
        uint256 protocolFee = _div(_mul(basePrice, PROTOCOL_FEE_PCT), 100);
        uint256 payout      = _sub(_sub(basePrice, creatorFee), protocolFee);

        // Update balances first (checks-effects-interactions)
        keySupply[_creator]  = _sub(supply, _amount);
        keyBalance[_creator][msg.sender] = _sub(keyBalance[_creator][msg.sender], _amount);

        // Pay seller
        require(
            IERC20Keys(paymentToken).transfer(msg.sender, payout),
            "sell payout failed"
        );

        // Distribute fees
        if (creatorFee > 0) {
            creatorEarnings[_creator] = _add(creatorEarnings[_creator], creatorFee);
        }
        if (protocolFee > 0) {
            require(
                IERC20Keys(paymentToken).transfer(protocolWallet, protocolFee),
                "protocol fee transfer failed"
            );
        }

        uint256 tradeId = nextTradeId;
        nextTradeId = _add(tradeId, 1);
        return tradeId;
    }

    // ── Claim Earnings ──────────────────────────────────────────
    /// @notice Creator claims accumulated royalty earnings
    function claimEarnings() external {
        uint256 amount = creatorEarnings[msg.sender];
        require(amount > 0, "no earnings");
        creatorEarnings[msg.sender] = 0;
        require(
            IERC20Keys(paymentToken).transfer(msg.sender, amount),
            "earnings transfer failed"
        );
    }

    // ── View Functions ──────────────────────────────────────────

    function getKeySupply(address _creator) external view returns (uint256) {
        return keySupply[_creator];
    }

    function getKeyBalance(address _creator, address _holder) external view returns (uint256) {
        return keyBalance[_creator][_holder];
    }

    function getCreatorEarnings(address _creator) external view returns (uint256) {
        return creatorEarnings[_creator];
    }

    function getIsRegistered(address _creator) external view returns (bool) {
        return isRegistered[_creator];
    }

    // ── Internal: bonding curve price for a range ───────────────
    /// @dev Sum of (supply + i)² * PRICE_SCALE / CURVE_DIVISOR for i in [0, amount)
    ///      Uses closed-form: sum(k², a, b) = sumSq(b) - sumSq(a-1)
    ///      where sumSq(n) = n*(n+1)*(2n+1)/6
    function _getPriceForRange(uint256 startSupply, uint256 amount) internal pure returns (uint256) {
        if (amount == 0) return 0;
        uint256 endVal = _add(startSupply, _sub(amount, 1));
        uint256 sumEnd = _div(_mul(_mul(endVal, _add(endVal, 1)), _add(_mul(2, endVal), 1)), 6);
        uint256 sumStart = 0;
        if (startSupply > 0) {
            uint256 s = _sub(startSupply, 1);
            sumStart = _div(_mul(_mul(s, _add(s, 1)), _add(_mul(2, s), 1)), 6);
        }
        return _div(_mul(_sub(sumEnd, sumStart), PRICE_SCALE), CURVE_DIVISOR);
    }

    // ── Admin ───────────────────────────────────────────────────

    function setProtocolWallet(address _newWallet) external {
        require(msg.sender == owner, "not owner");
        protocolWallet = _newWallet;
    }
}
