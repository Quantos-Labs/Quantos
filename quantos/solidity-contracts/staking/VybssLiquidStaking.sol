// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IstQTEST {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

/// @title VybssLiquidStaking
/// @notice Production liquid staking manager for QTEST -> stQTEST.
/// @dev The manager uses share accounting: stQTEST supply represents a claim on total pooled QTEST.
contract VybssLiquidStaking {
    uint256 public constant RATE_SCALE = 1e18;
    uint256 public constant MAX_FEE_BPS = 1_000; // 10%

    IERC20Like public immutable qtest;
    IstQTEST public immutable stqtest;

    address public owner;
    address public guardian;
    address public feeRecipient;

    bool public paused;
    uint256 public totalPooledQtest;
    uint256 public protocolFeeBps;
    uint256 public unbondingSeconds;
    uint256 public nextWithdrawalId;

    struct Withdrawal {
        address owner;
        uint256 stQtestBurned;
        uint256 qtestAmount;
        uint256 requestedAt;
        uint256 availableAt;
        bool claimed;
    }

    mapping(uint256 => Withdrawal) public withdrawals;
    mapping(address => uint256[]) private _accountWithdrawalIds;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GuardianUpdated(address indexed guardian);
    event ParamsUpdated(uint256 protocolFeeBps, uint256 unbondingSeconds, address indexed feeRecipient);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event Staked(address indexed user, uint256 qtestIn, uint256 fee, uint256 stQtestMinted, uint256 exchangeRate);
    event UnstakeRequested(
        address indexed user,
        uint256 indexed withdrawalId,
        uint256 stQtestBurned,
        uint256 qtestAmount,
        uint256 availableAt,
        uint256 exchangeRate
    );
    event Claimed(address indexed user, uint256 indexed withdrawalId, uint256 qtestAmount);
    event RewardsReported(address indexed reporter, uint256 amount, uint256 newTotalPooled);
    event Recovered(address indexed token, address indexed to, uint256 amount);

    constructor(
        address _qtest,
        address _stqtest,
        uint256 _unbondingSeconds,
        address _feeRecipient
    ) {
        require(_qtest != address(0), "Invalid QTEST");
        require(_stqtest != address(0), "Invalid stQTEST");
        qtest = IERC20Like(_qtest);
        stqtest = IstQTEST(_stqtest);
        owner = msg.sender;
        guardian = msg.sender;
        feeRecipient = _feeRecipient == address(0) ? msg.sender : _feeRecipient;
        unbondingSeconds = _unbondingSeconds;
        emit OwnershipTransferred(address(0), msg.sender);
        emit GuardianUpdated(msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyGuardianOrOwner() {
        require(msg.sender == owner || msg.sender == guardian, "Only guardian");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    function exchangeRate() public view returns (uint256) {
        uint256 supply = stqtest.totalSupply();
        if (supply == 0) return RATE_SCALE;
        return (totalPooledQtest * RATE_SCALE) / supply;
    }

    function previewStake(uint256 qtestAmount) public view returns (uint256 stQtestOut, uint256 fee) {
        require(qtestAmount > 0, "Zero amount");
        fee = (qtestAmount * protocolFeeBps) / 10_000;
        uint256 netAmount = qtestAmount - fee;
        uint256 supply = stqtest.totalSupply();
        if (supply == 0 || totalPooledQtest == 0) {
            stQtestOut = netAmount;
        } else {
            stQtestOut = (netAmount * supply) / totalPooledQtest;
        }
    }

    function previewUnstake(uint256 stQtestAmount) public view returns (uint256 qtestOut) {
        require(stQtestAmount > 0, "Zero amount");
        uint256 supply = stqtest.totalSupply();
        require(supply > 0 && totalPooledQtest > 0, "Empty pool");
        qtestOut = (stQtestAmount * totalPooledQtest) / supply;
    }

    function stake(uint256 qtestAmount) external whenNotPaused returns (uint256 stQtestMinted) {
        (uint256 shares, uint256 fee) = previewStake(qtestAmount);
        require(shares > 0, "Zero shares");
        require(qtest.transferFrom(msg.sender, address(this), qtestAmount), "QTEST transfer failed");

        if (fee > 0) {
            require(qtest.transfer(feeRecipient, fee), "Fee transfer failed");
        }

        uint256 netAmount = qtestAmount - fee;
        totalPooledQtest += netAmount;
        stqtest.mint(msg.sender, shares);

        emit Staked(msg.sender, qtestAmount, fee, shares, exchangeRate());
        return shares;
    }

    function requestUnstake(uint256 stQtestAmount) external whenNotPaused returns (uint256 withdrawalId) {
        uint256 qtestAmount = previewUnstake(stQtestAmount);
        require(qtestAmount > 0, "Zero QTEST");
        require(qtestAmount <= totalPooledQtest, "Insufficient pool");

        stqtest.burnFrom(msg.sender, stQtestAmount);
        totalPooledQtest -= qtestAmount;

        withdrawalId = nextWithdrawalId;
        nextWithdrawalId += 1;

        uint256 availableAt = block.timestamp + unbondingSeconds;
        withdrawals[withdrawalId] = Withdrawal({
            owner: msg.sender,
            stQtestBurned: stQtestAmount,
            qtestAmount: qtestAmount,
            requestedAt: block.timestamp,
            availableAt: availableAt,
            claimed: false
        });
        _accountWithdrawalIds[msg.sender].push(withdrawalId);

        emit UnstakeRequested(msg.sender, withdrawalId, stQtestAmount, qtestAmount, availableAt, exchangeRate());
    }

    function claim(uint256 withdrawalId) external whenNotPaused {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(w.owner == msg.sender, "Not owner");
        require(!w.claimed, "Already claimed");
        require(block.timestamp >= w.availableAt, "Unbonding");

        w.claimed = true;
        require(qtest.transfer(msg.sender, w.qtestAmount), "QTEST transfer failed");
        emit Claimed(msg.sender, withdrawalId, w.qtestAmount);
    }

    /// @notice Report externally accrued rewards into the pool.
    /// @dev Caller must approve QTEST first. In prod this should be restricted to a keeper/validator adapter.
    function reportRewards(uint256 amount) external onlyGuardianOrOwner {
        require(amount > 0, "Zero amount");
        require(qtest.transferFrom(msg.sender, address(this), amount), "QTEST transfer failed");
        totalPooledQtest += amount;
        emit RewardsReported(msg.sender, amount, totalPooledQtest);
    }

    function accountWithdrawalCount(address account) external view returns (uint256) {
        return _accountWithdrawalIds[account].length;
    }

    function accountWithdrawalId(address account, uint256 index) external view returns (uint256) {
        return _accountWithdrawalIds[account][index];
    }

    function getWithdrawal(uint256 withdrawalId)
        external
        view
        returns (
            address withdrawalOwner,
            uint256 stQtestBurned,
            uint256 qtestAmount,
            uint256 requestedAt,
            uint256 availableAt,
            bool claimed
        )
    {
        Withdrawal memory w = withdrawals[withdrawalId];
        return (w.owner, w.stQtestBurned, w.qtestAmount, w.requestedAt, w.availableAt, w.claimed);
    }

    function getProtocolInfo()
        external
        view
        returns (
            uint256 pooledQtest,
            uint256 stQtestSupply,
            uint256 rate,
            uint256 feeBps,
            uint256 cooldown,
            bool isPaused
        )
    {
        return (totalPooledQtest, stqtest.totalSupply(), exchangeRate(), protocolFeeBps, unbondingSeconds, paused);
    }

    function getAccountInfo(address account)
        external
        view
        returns (
            uint256 qtestBalance,
            uint256 stQtestBalance,
            uint256 qtestValue,
            uint256 withdrawalCount
        )
    {
        uint256 stBal = stqtest.balanceOf(account);
        qtestBalance = qtest.balanceOf(account);
        stQtestBalance = stBal;
        qtestValue = (stBal * exchangeRate()) / RATE_SCALE;
        withdrawalCount = _accountWithdrawalIds[account].length;
    }

    function setParams(uint256 newProtocolFeeBps, uint256 newUnbondingSeconds, address newFeeRecipient) external onlyOwner {
        require(newProtocolFeeBps <= MAX_FEE_BPS, "Fee too high");
        require(newFeeRecipient != address(0), "Invalid fee recipient");
        protocolFeeBps = newProtocolFeeBps;
        unbondingSeconds = newUnbondingSeconds;
        feeRecipient = newFeeRecipient;
        emit ParamsUpdated(newProtocolFeeBps, newUnbondingSeconds, newFeeRecipient);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "Invalid guardian");
        guardian = newGuardian;
        emit GuardianUpdated(newGuardian);
    }

    function pause() external onlyGuardianOrOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function recoverToken(address token, address to, uint256 amount) external onlyOwner {
        require(token != address(qtest), "Cannot recover pooled QTEST");
        require(to != address(0), "Invalid recipient");
        require(IERC20Like(token).transfer(to, amount), "Recover failed");
        emit Recovered(token, to, amount);
    }
}
