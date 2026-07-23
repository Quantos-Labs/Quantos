// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Pred {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssPrediction — Multi-outcome AMM prediction market for Quantos
/// @notice Supports 2-8 custom outcomes per market.  Binary YES/NO is just N=2.
///         Resolution: creator proposes → dispute → community Schelling-point vote.
contract VybssPrediction {

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Constants ───────────────────────────────────────────────
    uint256 public constant MAX_OUTCOMES     = 8;
    uint256 public constant FEE_BPS          = 200;      // 2 %
    uint256 public constant BPS              = 10000;
    uint256 public constant RESOLUTION_WINDOW = 72 hours;
    uint256 public constant DISPUTE_WINDOW    = 48 hours;
    uint256 public constant VOTE_WINDOW       = 72 hours;
    uint256 public constant VOTE_STAKE        = 5 * 10**18;      // 5 QTEST
    uint256 public constant MIN_VOTERS        = 3;
    uint256 public constant DISPUTE_BOND_QTEST  = 50 * 10**18;   // 50 QTEST
    uint256 public constant DISPUTE_BOND_SQTEST = 10 * 10**18;   // 10 SQTEST
    uint256 public constant CREATE_COST_QTEST   = 100 * 10**18;  // 100 QTEST
    uint256 public constant CREATE_COST_SQTEST  = 20 * 10**18;   // 20 SQTEST
    uint8   public constant OUTCOME_INVALID  = 255;

    // ── Accepted collateral tokens ──────────────────────────────
    address public immutable qtest;
    address public immutable sqtest;

    // ── Enums ───────────────────────────────────────────────────
    // Status: 0=Active, 1=PendingResolution, 2=Disputed, 3=Resolved
    uint8 public constant STATUS_ACTIVE             = 0;
    uint8 public constant STATUS_PENDING_RESOLUTION = 1;
    uint8 public constant STATUS_DISPUTED           = 2;
    uint8 public constant STATUS_RESOLVED           = 3;

    // ResolutionType: 0=SelfReported, 1=PublicSource, 2=Community
    uint8 public constant RES_SELF_REPORTED = 0;
    uint8 public constant RES_PUBLIC_SOURCE = 1;
    uint8 public constant RES_COMMUNITY     = 2;

    // ── Market struct ───────────────────────────────────────────
    struct Market {
        address creator;
        address collateralToken;      // QTEST or SQTEST
        uint8   numOutcomes;          // 2..8
        uint8   resolutionType;       // SelfReported / PublicSource / Community
        uint8   status;

        uint256 endDate;
        uint256 creatorStake;         // initial liquidity = creation cost
        uint256 accumulatedFees;

        // AMM pools (constant product across N outcomes)
        uint256[8] pools;

        // Resolution fields
        uint8   proposedOutcome;      // index or OUTCOME_INVALID
        address proposer;
        uint256 proposalDeadline;     // end of dispute window

        // Dispute
        address disputer;
        uint256 disputeBond;
        uint256 voteDeadline;

        // Votes  (only non-holders can vote)
        uint256[8] votes;             // votes per outcome index
        uint256    votesInvalid;
        uint256    totalVoteStake;    // total staked by voters

        // Final
        uint8   finalOutcome;         // index or OUTCOME_INVALID
        bool    resolved;
    }

    // ── Storage ─────────────────────────────────────────────────
    uint256 public nextMarketId;
    mapping(uint256 => Market) public markets;

    // Per-user share balances:  marketId → user → outcomeIndex → shares
    mapping(uint256 => mapping(address => uint256[8])) public shares;
    // Track if user ever held shares (to block voting)
    mapping(uint256 => mapping(address => bool)) public everHeldShares;
    // Track claims
    mapping(uint256 => mapping(address => bool)) public claimed;
    // Vote tracking
    mapping(uint256 => mapping(address => uint8))   public voterChoice;   // 0xFF = not voted
    mapping(uint256 => mapping(address => bool))    public hasVoted;
    // Vote reward tracking
    mapping(uint256 => mapping(address => bool))    public voteRewardClaimed;

    // ── Events ──────────────────────────────────────────────────
    event MarketCreated(uint256 indexed marketId, address indexed creator, uint8 numOutcomes, address collateral, uint256 endDate);
    event SharesBought(uint256 indexed marketId, address indexed buyer, uint8 outcomeIndex, uint256 sharesOut, uint256 cost);
    event SharesSold(uint256 indexed marketId, address indexed seller, uint8 outcomeIndex, uint256 sharesIn, uint256 payout);
    event ResolutionProposed(uint256 indexed marketId, address indexed proposer, uint8 outcome);
    event MarketDisputed(uint256 indexed marketId, address indexed disputer, uint256 bond);
    event VoteCast(uint256 indexed marketId, address indexed voter, uint8 outcome, uint256 stake);
    event MarketResolved(uint256 indexed marketId, uint8 finalOutcome);
    event Claimed(uint256 indexed marketId, address indexed user, uint256 amount);
    event FeesClaimed(uint256 indexed marketId, address indexed creator, uint256 amount);
    event VoteRewardClaimed(uint256 indexed marketId, address indexed voter, uint256 amount);

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _qtest, address _sqtest) {
        require(_qtest != address(0) && _sqtest != address(0), "Zero addr");
        qtest  = _qtest;
        sqtest = _sqtest;
    }

    // ═════════════════════════════════════════════════════════════
    // 1. CREATE MARKET
    // ═════════════════════════════════════════════════════════════

    /// @notice Create a new prediction market with N custom outcomes.
    /// @param numOutcomes Number of outcomes (2-8)
    /// @param collateralToken QTEST or SQTEST address
    /// @param endDate UNIX timestamp when trading ends
    /// @param resolutionType 0=SelfReported, 1=PublicSource, 2=Community
    function createMarket(
        uint8   numOutcomes,
        address collateralToken,
        uint256 endDate,
        uint8   resolutionType
    ) external returns (uint256 marketId) {
        require(numOutcomes >= 2 && numOutcomes <= MAX_OUTCOMES, "Bad N");
        require(collateralToken == qtest || collateralToken == sqtest, "Bad token");
        require(endDate > block.timestamp, "End in past");
        require(resolutionType <= RES_COMMUNITY, "Bad res type");

        uint256 cost;
        if (collateralToken == qtest) {
            cost = CREATE_COST_QTEST;
        } else {
            cost = CREATE_COST_SQTEST;
        }

        require(
            IERC20Pred(collateralToken).transferFrom(msg.sender, address(this), cost),
            "Transfer failed"
        );

        marketId = nextMarketId;
        nextMarketId += 1;

        Market storage m = markets[marketId];
        m.creator         = msg.sender;
        m.collateralToken = collateralToken;
        m.numOutcomes     = numOutcomes;
        m.resolutionType  = resolutionType;
        m.status          = STATUS_ACTIVE;
        m.endDate         = endDate;
        m.creatorStake    = cost;
        m.proposedOutcome = OUTCOME_INVALID;
        m.finalOutcome    = OUTCOME_INVALID;

        // Split liquidity equally across N pools
        uint256 perPool = _div(cost, uint256(numOutcomes));
        for (uint8 i = 0; i < numOutcomes; i++) {
            m.pools[i] = perPool;
        }

        emit MarketCreated(marketId, msg.sender, numOutcomes, collateralToken, endDate);
    }

    // ═════════════════════════════════════════════════════════════
    // 2. AMM TRADING
    // ═════════════════════════════════════════════════════════════

    /// @notice Buy outcome shares. Caller pays `amount` collateral, receives shares.
    function buyShares(uint256 marketId, uint8 outcomeIndex, uint256 amount) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_ACTIVE, "Not active");
        require(block.timestamp < m.endDate, "Ended");
        require(outcomeIndex < m.numOutcomes, "Bad outcome");
        require(amount > 0, "Zero amount");

        // Transfer collateral in
        require(
            IERC20Pred(m.collateralToken).transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );

        // Fee
        uint256 fee = _div(_mul(amount, FEE_BPS), BPS);
        uint256 netAmount = amount - fee;
        m.accumulatedFees += fee;

        // AMM: add netAmount to ALL pools, then withdraw from outcome pool
        uint256 sharesOut = _calcBuyShares(m, outcomeIndex, netAmount);
        require(sharesOut > 0, "Zero shares");

        // Update pools: add netAmount to all, subtract sharesOut from target
        for (uint8 i = 0; i < m.numOutcomes; i++) {
            m.pools[i] += netAmount;
        }
        m.pools[outcomeIndex] -= sharesOut;

        // Credit shares
        shares[marketId][msg.sender][outcomeIndex] += sharesOut;
        everHeldShares[marketId][msg.sender] = true;

        emit SharesBought(marketId, msg.sender, outcomeIndex, sharesOut, amount);
    }

    /// @notice Sell outcome shares back to the pool.
    function sellShares(uint256 marketId, uint8 outcomeIndex, uint256 sharesIn) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_ACTIVE, "Not active");
        require(block.timestamp < m.endDate, "Ended");
        require(outcomeIndex < m.numOutcomes, "Bad outcome");
        require(sharesIn > 0, "Zero shares");
        require(shares[marketId][msg.sender][outcomeIndex] >= sharesIn, "Not enough");

        // AMM: add shares back to outcome pool, remove collateral from all pools
        uint256 payout = _calcSellPayout(m, outcomeIndex, sharesIn);
        require(payout > 0, "Zero payout");

        // Fee on payout
        uint256 fee = _div(_mul(payout, FEE_BPS), BPS);
        uint256 netPayout = payout - fee;
        m.accumulatedFees += fee;

        // Update pools: add sharesIn to target, subtract payout from all
        m.pools[outcomeIndex] += sharesIn;
        for (uint8 i = 0; i < m.numOutcomes; i++) {
            m.pools[i] -= _div(payout, uint256(m.numOutcomes));
        }

        // Debit shares
        shares[marketId][msg.sender][outcomeIndex] -= sharesIn;

        // Transfer collateral out
        require(
            IERC20Pred(m.collateralToken).transfer(msg.sender, netPayout),
            "Transfer failed"
        );

        emit SharesSold(marketId, msg.sender, outcomeIndex, sharesIn, netPayout);
    }

    // ── AMM Math ────────────────────────────────────────────────
    // Constant-product across N pools:  ∏ pools[i] = k
    // All math avoids computing full product to prevent uint256 overflow.

    /// @dev Calculate shares received when buying `amount` of outcome `idx`
    /// Uses iterative multiply-divide to keep intermediate values small.
    /// Equivalent to: shares = pools[idx] + amount - k / ∏(pools[j] + amount for j≠idx)
    /// Rewritten as:  newPool = pools[idx] * ∏(pools[j] / (pools[j] + amount)) for j≠idx
    function _calcBuyShares(Market storage m, uint8 idx, uint256 amount)
        internal view returns (uint256)
    {
        // Iterative ratio: avoids computing full product k
        // newPool = pools[idx] * ∏_{j≠idx}( pools[j] / (pools[j] + amount) )
        // At each step: ratio = ratio * pools[j] / (pools[j] + amount)
        // Intermediate values stay in the range of individual pool sizes.
        uint256 ratio = m.pools[idx];
        for (uint8 j = 0; j < m.numOutcomes; j++) {
            if (j != idx) {
                ratio = _div(_mul(ratio, m.pools[j]), m.pools[j] + amount);
            }
        }
        // shares = (pools[idx] + amount) - newPool
        uint256 sharesOut = (m.pools[idx] + amount) - ratio;
        return sharesOut;
    }

    /// @dev Calculate collateral received when selling `sharesIn` of outcome `idx`
    /// Uses 1e36-scaled reciprocals to avoid full product overflow.
    function _calcSellPayout(Market storage m, uint8 idx, uint256 sharesIn)
        internal view returns (uint256)
    {
        // price_i = (1/pools[i]) / Σ(1/pools[j])
        // Use SCALE = 1e36 to maintain precision with 18-decimal pools
        uint256 SCALE = 1e36;
        uint256 sumRecip = 0;
        for (uint8 j = 0; j < m.numOutcomes; j++) {
            if (m.pools[j] == 0) return 0;
            sumRecip += _div(SCALE, m.pools[j]);
        }
        if (sumRecip == 0) return 0;

        uint256 myRecip = _div(SCALE, m.pools[idx]);
        // price in 1e18 scale
        uint256 price = _div(_mul(myRecip, 1e18), sumRecip);
        // payout = sharesIn * price / 1e18
        uint256 payout = _div(_mul(sharesIn, price), 1e18);
        return payout;
    }

    // ── View: get outcome price ─────────────────────────────────

    /// @notice Get the price of an outcome (0..1e18 scale, where 1e18 = 100%)
    /// CPMM price: price_i = (1/pools[i]) / Σ(1/pools[j])
    /// Uses 1e36-scaled reciprocals to avoid full product overflow.
    function getOutcomePrice(uint256 marketId, uint8 outcomeIndex) external view returns (uint256) {
        Market storage m = markets[marketId];
        require(outcomeIndex < m.numOutcomes, "Bad outcome");

        uint256 SCALE = 1e36;
        uint256 sumRecip = 0;
        for (uint8 j = 0; j < m.numOutcomes; j++) {
            if (m.pools[j] == 0) return 0;
            sumRecip += _div(SCALE, m.pools[j]);
        }
        if (sumRecip == 0) return 0;

        uint256 myRecip = _div(SCALE, m.pools[outcomeIndex]);
        return _div(_mul(myRecip, 1e18), sumRecip);
    }

    /// @notice Get all pool values for a market
    function getMarketPools(uint256 marketId) external view returns (uint256[8] memory) {
        return markets[marketId].pools;
    }

    /// @notice Get user shares for all outcomes in a market
    function getUserShares(uint256 marketId, address user) external view returns (uint256[8] memory) {
        return shares[marketId][user];
    }

    /// @notice Get market base info
    function getMarketInfo(uint256 marketId) external view returns (
        address creator,
        address collateralToken,
        uint8   numOutcomes,
        uint8   resolutionType,
        uint8   status,
        uint256 endDate,
        uint256 creatorStake,
        uint256 accumulatedFees
    ) {
        Market storage m = markets[marketId];
        return (m.creator, m.collateralToken, m.numOutcomes, m.resolutionType,
                m.status, m.endDate, m.creatorStake, m.accumulatedFees);
    }

    /// @notice Get market resolution info
    function getResolutionInfo(uint256 marketId) external view returns (
        uint8   proposedOutcome,
        address proposer,
        uint256 proposalDeadline,
        address disputer,
        uint256 disputeBond,
        uint256 voteDeadline,
        uint256 votesInvalid,
        uint8   finalOutcome,
        bool    resolved
    ) {
        Market storage m = markets[marketId];
        return (m.proposedOutcome, m.proposer, m.proposalDeadline,
                m.disputer, m.disputeBond, m.voteDeadline,
                m.votesInvalid, m.finalOutcome, m.resolved);
    }

    /// @notice Get votes per outcome
    function getVotes(uint256 marketId) external view returns (uint256[8] memory, uint256) {
        return (markets[marketId].votes, markets[marketId].votesInvalid);
    }

    // ═════════════════════════════════════════════════════════════
    // 3. RESOLUTION
    // ═════════════════════════════════════════════════════════════

    /// @notice Creator (or anyone after timeout) proposes the winning outcome.
    function proposeResolution(uint256 marketId, uint8 outcome) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_ACTIVE, "Not active");
        require(block.timestamp >= m.endDate, "Not ended");

        if (block.timestamp < m.endDate + RESOLUTION_WINDOW) {
            // Within 72h → only creator can propose
            require(msg.sender == m.creator, "Only creator");
        }
        // After 72h → anyone can propose (must be a valid outcome or INVALID)
        require(outcome < m.numOutcomes || outcome == OUTCOME_INVALID, "Bad outcome");

        m.proposedOutcome    = outcome;
        m.proposer           = msg.sender;
        m.proposalDeadline   = block.timestamp + DISPUTE_WINDOW;
        m.status             = STATUS_PENDING_RESOLUTION;

        emit ResolutionProposed(marketId, msg.sender, outcome);
    }

    /// @notice Finalize if dispute window passed without dispute.
    function finalizeResolution(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_PENDING_RESOLUTION, "Not pending");
        require(block.timestamp >= m.proposalDeadline, "Dispute window open");

        _finalize(marketId, m.proposedOutcome);
    }

    // ═════════════════════════════════════════════════════════════
    // 4. DISPUTE
    // ═════════════════════════════════════════════════════════════

    /// @notice Dispute the proposed resolution. Requires posting a bond.
    function dispute(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_PENDING_RESOLUTION, "Not pending");
        require(block.timestamp < m.proposalDeadline, "Window closed");
        require(msg.sender != m.proposer, "Proposer cannot dispute");

        uint256 bond;
        if (m.collateralToken == qtest) {
            bond = DISPUTE_BOND_QTEST;
        } else {
            bond = DISPUTE_BOND_SQTEST;
        }

        require(
            IERC20Pred(m.collateralToken).transferFrom(msg.sender, address(this), bond),
            "Bond transfer failed"
        );

        m.disputer      = msg.sender;
        m.disputeBond   = bond;
        m.voteDeadline  = block.timestamp + VOTE_WINDOW;
        m.status        = STATUS_DISPUTED;

        emit MarketDisputed(marketId, msg.sender, bond);
    }

    // ═════════════════════════════════════════════════════════════
    // 5. COMMUNITY VOTE  (Schelling point)
    // ═════════════════════════════════════════════════════════════

    /// @notice Cast a vote.  Only users who NEVER held shares can vote.
    ///         Voter stakes VOTE_STAKE (5 QTEST) in the market's collateral token.
    function castVote(uint256 marketId, uint8 outcome) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_DISPUTED, "Not disputed");
        require(block.timestamp < m.voteDeadline, "Vote ended");
        require(!everHeldShares[marketId][msg.sender], "Had position");
        require(!hasVoted[marketId][msg.sender], "Already voted");
        require(outcome < m.numOutcomes || outcome == OUTCOME_INVALID, "Bad outcome");

        // Stake
        require(
            IERC20Pred(m.collateralToken).transferFrom(msg.sender, address(this), VOTE_STAKE),
            "Stake transfer failed"
        );

        hasVoted[marketId][msg.sender]    = true;
        voterChoice[marketId][msg.sender] = outcome;
        m.totalVoteStake += VOTE_STAKE;

        if (outcome == OUTCOME_INVALID) {
            m.votesInvalid += 1;
        } else {
            m.votes[outcome] += 1;
        }

        emit VoteCast(marketId, msg.sender, outcome, VOTE_STAKE);
    }

    /// @notice Finalize a disputed market after vote window.
    function finalizeVote(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(m.status == STATUS_DISPUTED, "Not disputed");
        require(block.timestamp >= m.voteDeadline, "Vote ongoing");

        // Count total votes
        uint256 totalVotes = m.votesInvalid;
        for (uint8 i = 0; i < m.numOutcomes; i++) {
            totalVotes += m.votes[i];
        }

        // Minimum voters check
        if (totalVotes < MIN_VOTERS) {
            // Not enough voters → INVALID
            _finalize(marketId, OUTCOME_INVALID);
            return;
        }

        // Find winning outcome (most votes)
        uint8 winningOutcome = OUTCOME_INVALID;
        uint256 maxVotes = m.votesInvalid;

        for (uint8 i = 0; i < m.numOutcomes; i++) {
            if (m.votes[i] > maxVotes) {
                maxVotes = m.votes[i];
                winningOutcome = i;
            }
        }

        // Distribute dispute rewards
        bool proposerWins = (winningOutcome == m.proposedOutcome);

        if (proposerWins) {
            // Proposer was correct → disputer loses bond → proposer gets bond
            IERC20Pred(m.collateralToken).transfer(m.proposer, m.disputeBond);
        } else {
            // Disputer was correct → disputer gets bond back + portion of creator stake
            uint256 reward = _div(m.creatorStake, 4); // 25% of creator stake as reward
            IERC20Pred(m.collateralToken).transfer(m.disputer, m.disputeBond + reward);
            m.creatorStake -= reward;
        }

        _finalize(marketId, winningOutcome);
    }

    /// @notice Claim vote reward (majority voters get minority stakes).
    function claimVoteReward(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(m.resolved, "Not resolved");
        require(hasVoted[marketId][msg.sender], "Not voter");
        require(!voteRewardClaimed[marketId][msg.sender], "Already claimed");

        uint8 myChoice = voterChoice[marketId][msg.sender];
        bool inMajority = (myChoice == m.finalOutcome);

        voteRewardClaimed[marketId][msg.sender] = true;

        if (inMajority) {
            // Count majority and minority voters
            uint256 majorityCount;
            uint256 totalVotes = m.votesInvalid;
            for (uint8 i = 0; i < m.numOutcomes; i++) {
                totalVotes += m.votes[i];
            }

            if (m.finalOutcome == OUTCOME_INVALID) {
                majorityCount = m.votesInvalid;
            } else {
                majorityCount = m.votes[m.finalOutcome];
            }

            uint256 minorityCount = totalVotes - majorityCount;
            uint256 minorityStake = _mul(minorityCount, VOTE_STAKE);

            // Reward = own stake back + share of minority stakes
            uint256 reward = VOTE_STAKE + _div(minorityStake, majorityCount);

            IERC20Pred(m.collateralToken).transfer(msg.sender, reward);
            emit VoteRewardClaimed(marketId, msg.sender, reward);
        }
        // Minority voters: lose their stake (no transfer)
    }

    // ═════════════════════════════════════════════════════════════
    // 6. CLAIM WINNINGS
    // ═════════════════════════════════════════════════════════════

    /// @notice Claim winnings after market is resolved.
    function claimWinnings(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(m.resolved, "Not resolved");
        require(!claimed[marketId][msg.sender], "Already claimed");

        claimed[marketId][msg.sender] = true;

        if (m.finalOutcome == OUTCOME_INVALID) {
            // INVALID → refund pro-rata based on total shares held
            uint256 totalUserShares = 0;
            for (uint8 i = 0; i < m.numOutcomes; i++) {
                totalUserShares += shares[marketId][msg.sender][i];
            }
            if (totalUserShares == 0) return;

            // Total shares across all users and outcomes → approximate via pool totals
            uint256 totalPool = 0;
            for (uint8 i = 0; i < m.numOutcomes; i++) {
                totalPool += m.pools[i];
            }
            // Refund proportional to user's total shares
            uint256 contractBalance = IERC20Pred(m.collateralToken).balanceOf(address(this));
            uint256 refund = _div(_mul(totalUserShares, contractBalance), totalPool + totalUserShares);
            if (refund > 0) {
                IERC20Pred(m.collateralToken).transfer(msg.sender, refund);
            }
            emit Claimed(marketId, msg.sender, refund);
        } else {
            // Winner outcome → 1 collateral per share
            uint256 winningShares = shares[marketId][msg.sender][m.finalOutcome];
            if (winningShares == 0) return;

            IERC20Pred(m.collateralToken).transfer(msg.sender, winningShares);
            emit Claimed(marketId, msg.sender, winningShares);
        }
    }

    /// @notice Creator claims accumulated trading fees.
    function claimFees(uint256 marketId) external {
        Market storage m = markets[marketId];
        require(msg.sender == m.creator, "Not creator");
        require(m.accumulatedFees > 0, "No fees");

        uint256 fees = m.accumulatedFees;
        m.accumulatedFees = 0;

        IERC20Pred(m.collateralToken).transfer(msg.sender, fees);
        emit FeesClaimed(marketId, msg.sender, fees);
    }

    // ═════════════════════════════════════════════════════════════
    // INTERNAL
    // ═════════════════════════════════════════════════════════════

    function _finalize(uint256 marketId, uint8 outcome) internal {
        Market storage m = markets[marketId];
        m.finalOutcome = outcome;
        m.resolved     = true;
        m.status       = STATUS_RESOLVED;
        emit MarketResolved(marketId, outcome);
    }
}
