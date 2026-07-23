// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// =============================================================================
// VybssInsurancePool V1
// Single pool backing two cover products:
//   Product 0 — VybssLiquidStaking smart-contract risk
//   Product 1 — VybssRestakingVault smart-contract risk
//
// Underwriters deposit stQTEST (or QTEST auto-staked on the frontend) and
// receive insQTEST shares.  Coverage buyers pay a premium in stQTEST and get
// a policy ID.  Claims are submitted on-chain and approved/rejected by the
// guardian/owner.  No slashing in V1.
// =============================================================================

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IInsQTEST {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

contract VybssInsurancePool {
    IERC20Like public immutable stqtest;
    IInsQTEST  public immutable insqtest;

    address public owner;
    address public guardian;
    bool    public paused;

    // Basis points: annual premium charged to coverage buyers (e.g. 200 = 2 %)
    uint256 public premiumRateBps;
    // Max total exposure relative to capital (e.g. 10000 = 10x)
    uint256 public coverageRatioBps;
    // Cooldown in seconds before underwriters can claim their stQTEST back
    uint256 public cooldownSeconds;

    // stQTEST held in the pool (deposits + premiums - payouts - queued withdrawals)
    uint256 public totalCapital;
    // Sum of active cover amounts
    uint256 public totalExposure;

    uint256 public nextWithdrawalId;
    uint256 public nextPolicyId;

    // --- Structs ---

    struct Withdrawal {
        address owner;
        uint256 insAmount;
        uint256 stqtestAmount;
        uint256 availableAt;
        bool    claimed;
    }

    // status: 0=Active 1=Expired 2=ClaimPending 3=ClaimApproved 4=ClaimRejected
    struct Policy {
        address holder;
        uint256 coveredProduct;   // 0=LiquidStaking 1=RestakingVault
        uint256 coverAmount;
        uint256 premiumPaid;
        uint256 startsAt;
        uint256 expiresAt;
        uint256 status;
    }

    mapping(uint256 => Withdrawal) public withdrawals;
    mapping(address => uint256[])  private _accountWithdrawals;

    mapping(uint256 => Policy)     public policies;
    mapping(address => uint256[])  private _accountPolicies;

    // --- Events ---
    event Deposited(address indexed account, uint256 stqtestIn, uint256 insMinted);
    event WithdrawRequested(address indexed account, uint256 indexed withdrawalId, uint256 insAmount, uint256 stqtestAmount, uint256 availableAt);
    event WithdrawClaimed(address indexed account, uint256 indexed withdrawalId, uint256 stqtestAmount);
    event CoverPurchased(address indexed holder, uint256 indexed policyId, uint256 coveredProduct, uint256 coverAmount, uint256 expiresAt);
    event ClaimSubmitted(address indexed holder, uint256 indexed policyId);
    event ClaimApproved(uint256 indexed policyId, uint256 payout);
    event ClaimRejected(uint256 indexed policyId);
    event PolicyExpired(uint256 indexed policyId);
    event RewardsAdded(uint256 amount);

    // --- Modifiers ---
    modifier onlyOwner() { require(msg.sender == owner, "only owner"); _; }
    modifier onlyGuardianOrOwner() { require(msg.sender == owner || msg.sender == guardian, "only guardian"); _; }
    modifier whenNotPaused() { require(!paused, "paused"); _; }

    constructor(
        address _stqtest,
        address _insqtest,
        uint256 _premiumRateBps,
        uint256 _coverageRatioBps,
        uint256 _cooldownSeconds
    ) {
        require(_stqtest  != address(0), "bad stqtest");
        require(_insqtest != address(0), "bad insqtest");
        stqtest          = IERC20Like(_stqtest);
        insqtest         = IInsQTEST(_insqtest);
        owner            = msg.sender;
        guardian         = msg.sender;
        premiumRateBps   = _premiumRateBps;
        coverageRatioBps = _coverageRatioBps;
        cooldownSeconds  = _cooldownSeconds;
    }

    // -------------------------------------------------------------------------
    // Pool math  (all client-side-safe: no cross-contract calls in view fns)
    // -------------------------------------------------------------------------

    /// @notice Maximum total coverage the pool can underwrite given current capital.
    function maxCoverage() public view returns (uint256) {
        return (totalCapital * coverageRatioBps) / 10_000;
    }

    /// @notice Remaining coverage capacity.
    function availableCapacity() public view returns (uint256) {
        uint256 max = maxCoverage();
        return max > totalExposure ? max - totalExposure : 0;
    }

    /// @notice Premium in stQTEST for a given cover amount and duration.
    function premiumFor(uint256 coverAmount, uint256 durationDays) public view returns (uint256) {
        return (coverAmount * premiumRateBps * durationDays) / (365 * 10_000);
    }

    // -------------------------------------------------------------------------
    // Underwriting
    // -------------------------------------------------------------------------

    /// @notice Deposit stQTEST; receive insQTEST shares proportional to pool.
    function depositStQtest(uint256 stqtestAmount) external whenNotPaused returns (uint256 insMinted) {
        require(stqtestAmount > 0, "zero");
        uint256 supply = insqtest.totalSupply();
        insMinted = (totalCapital == 0 || supply == 0) ? stqtestAmount : (stqtestAmount * supply) / totalCapital;
        require(stqtest.transferFrom(msg.sender, address(this), stqtestAmount), "transfer failed");
        totalCapital += stqtestAmount;
        insqtest.mint(msg.sender, insMinted);
        emit Deposited(msg.sender, stqtestAmount, insMinted);
    }

    /// @notice Burn insQTEST and start a cooldown withdrawal.
    function requestWithdraw(uint256 insAmount) external whenNotPaused returns (uint256 withdrawalId) {
        require(insAmount > 0, "zero");
        uint256 supply = insqtest.totalSupply();
        require(supply > 0, "empty pool");
        uint256 stqtestOut = (insAmount * totalCapital) / supply;
        require(stqtestOut <= totalCapital, "exceeds capital");
        insqtest.burn(msg.sender, insAmount);
        totalCapital -= stqtestOut;
        withdrawalId = nextWithdrawalId++;
        uint256 avail = block.timestamp + cooldownSeconds;
        withdrawals[withdrawalId] = Withdrawal(msg.sender, insAmount, stqtestOut, avail, false);
        _accountWithdrawals[msg.sender].push(withdrawalId);
        emit WithdrawRequested(msg.sender, withdrawalId, insAmount, stqtestOut, avail);
    }

    /// @notice Claim stQTEST after cooldown.
    function claimWithdraw(uint256 withdrawalId) external whenNotPaused {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(w.owner == msg.sender,           "not owner");
        require(!w.claimed,                      "already claimed");
        require(block.timestamp >= w.availableAt,"cooldown");
        w.claimed = true;
        require(stqtest.transfer(msg.sender, w.stqtestAmount), "transfer failed");
        emit WithdrawClaimed(msg.sender, withdrawalId, w.stqtestAmount);
    }

    // -------------------------------------------------------------------------
    // Coverage
    // -------------------------------------------------------------------------

    /// @notice Purchase coverage for `durationDays` days.
    /// @param coveredProduct 0 = LiquidStaking, 1 = RestakingVault
    function buyCoverage(uint256 coveredProduct, uint256 coverAmount, uint256 durationDays)
        external whenNotPaused returns (uint256 policyId)
    {
        require(coveredProduct <= 1,           "unknown product");
        require(coverAmount > 0,               "zero cover");
        require(durationDays >= 1 && durationDays <= 365, "bad duration");
        require(coverAmount <= availableCapacity(), "exceeds capacity");
        uint256 premium = premiumFor(coverAmount, durationDays);
        require(premium > 0, "premium too small");
        require(stqtest.transferFrom(msg.sender, address(this), premium), "premium failed");
        totalCapital  += premium; // premiums accrue to underwriters
        totalExposure += coverAmount;
        policyId = nextPolicyId++;
        uint256 starts  = block.timestamp;
        uint256 expires = block.timestamp + durationDays * 1 days;
        policies[policyId] = Policy(msg.sender, coveredProduct, coverAmount, premium, starts, expires, 0);
        _accountPolicies[msg.sender].push(policyId);
        emit CoverPurchased(msg.sender, policyId, coveredProduct, coverAmount, expires);
    }

    /// @notice Submit a claim on an active policy.
    function submitClaim(uint256 policyId) external whenNotPaused {
        Policy storage p = policies[policyId];
        require(p.holder == msg.sender,         "not holder");
        require(p.status == 0,                  "not active");
        require(block.timestamp <= p.expiresAt, "expired");
        p.status = 2; // ClaimPending
        emit ClaimSubmitted(msg.sender, policyId);
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    function approveClaim(uint256 policyId) external onlyGuardianOrOwner {
        Policy storage p = policies[policyId];
        require(p.status == 2, "not pending");
        require(totalCapital >= p.coverAmount, "insufficient capital");
        p.status = 3; // ClaimApproved
        totalCapital  -= p.coverAmount;
        totalExposure -= p.coverAmount;
        require(stqtest.transfer(p.holder, p.coverAmount), "payout failed");
        emit ClaimApproved(policyId, p.coverAmount);
    }

    function rejectClaim(uint256 policyId) external onlyGuardianOrOwner {
        Policy storage p = policies[policyId];
        require(p.status == 2, "not pending");
        p.status = 4; // ClaimRejected
        totalExposure -= p.coverAmount;
        emit ClaimRejected(policyId);
    }

    function expirePolicy(uint256 policyId) external onlyGuardianOrOwner {
        Policy storage p = policies[policyId];
        require(p.status == 0 && block.timestamp > p.expiresAt, "not expired");
        p.status = 1; // Expired
        totalExposure -= p.coverAmount;
        emit PolicyExpired(policyId);
    }

    function addRewards(uint256 amount) external onlyGuardianOrOwner {
        require(stqtest.transferFrom(msg.sender, address(this), amount), "transfer failed");
        totalCapital += amount;
        emit RewardsAdded(amount);
    }

    function setPremiumRate(uint256 bps) external onlyOwner { premiumRateBps = bps; }
    function setCoverageRatio(uint256 bps) external onlyOwner { coverageRatioBps = bps; }
    function setCooldown(uint256 secs) external onlyGuardianOrOwner { cooldownSeconds = secs; }
    function pause() external onlyGuardianOrOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
    function setGuardian(address g) external onlyOwner { guardian = g; }
    function transferOwnership(address newOwner) external onlyOwner { owner = newOwner; }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    function accountWithdrawalCount(address account) external view returns (uint256) {
        return _accountWithdrawals[account].length;
    }
    function accountWithdrawalId(address account, uint256 index) external view returns (uint256) {
        return _accountWithdrawals[account][index];
    }
    function accountPolicyCount(address account) external view returns (uint256) {
        return _accountPolicies[account].length;
    }
    function accountPolicyId(address account, uint256 index) external view returns (uint256) {
        return _accountPolicies[account][index];
    }
}
