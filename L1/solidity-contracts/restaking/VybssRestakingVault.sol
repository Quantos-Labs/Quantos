// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IRstQTEST {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

/// @title VybssRestakingVault
/// @notice Restaking vault for stQTEST -> rstQTEST with cooldown withdrawal queue.
/// @dev No slashing in V1. Rewards can be reported by guardian/owner by depositing stQTEST into the vault.
contract VybssRestakingVault {
    uint256 public constant RATE_SCALE = 1e18;

    IERC20Like public immutable stqtest;
    IRstQTEST public immutable rstqtest;

    address public owner;
    address public guardian;
    bool public paused;
    uint256 public cooldownSeconds;

    // Assets (stQTEST) backing active rstQTEST shares, excluding amounts queued for withdrawal.
    uint256 public totalRestakedStqtest;
    uint256 public nextWithdrawalId;

    struct Withdrawal {
        address owner;
        uint256 rstBurned;
        uint256 stQtestAmount;
        uint256 requestedAt;
        uint256 availableAt;
        bool claimed;
    }

    mapping(uint256 => Withdrawal) public withdrawals;
    mapping(address => uint256[]) private _accountWithdrawalIds;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GuardianUpdated(address indexed guardian);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event CooldownUpdated(uint256 cooldownSeconds);

    event Deposited(address indexed user, uint256 stQtestIn, uint256 rstMinted, uint256 exchangeRate);
    event WithdrawRequested(
        address indexed user,
        uint256 indexed withdrawalId,
        uint256 rstBurned,
        uint256 stQtestAmount,
        uint256 availableAt,
        uint256 exchangeRate
    );
    event Claimed(address indexed user, uint256 indexed withdrawalId, uint256 stQtestAmount);
    event RewardsReported(address indexed reporter, uint256 stQtestAmount, uint256 newTotalRestaked);
    event Recovered(address indexed token, address indexed to, uint256 amount);

    constructor(address _stqtest, address _rstqtest, uint256 _cooldownSeconds) {
        require(_stqtest != address(0), "Invalid stQTEST");
        require(_rstqtest != address(0), "Invalid rstQTEST");
        stqtest = IERC20Like(_stqtest);
        rstqtest = IRstQTEST(_rstqtest);
        owner = msg.sender;
        guardian = msg.sender;
        cooldownSeconds = _cooldownSeconds;
        emit OwnershipTransferred(address(0), msg.sender);
        emit GuardianUpdated(msg.sender);
        emit CooldownUpdated(_cooldownSeconds);
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

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "Invalid guardian");
        guardian = newGuardian;
        emit GuardianUpdated(newGuardian);
    }

    function setCooldownSeconds(uint256 secs) external onlyGuardianOrOwner {
        cooldownSeconds = secs;
        emit CooldownUpdated(secs);
    }

    function pause() external onlyGuardianOrOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyGuardianOrOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function exchangeRate() public view returns (uint256) {
        uint256 supply = rstqtest.totalSupply();
        if (supply == 0) return RATE_SCALE;
        return (totalRestakedStqtest * RATE_SCALE) / supply;
    }

    function previewDeposit(uint256 stQtestAmount) public view returns (uint256 rstOut) {
        require(stQtestAmount > 0, "Zero amount");
        uint256 supply = rstqtest.totalSupply();
        if (supply == 0 || totalRestakedStqtest == 0) {
            return stQtestAmount;
        }
        return (stQtestAmount * supply) / totalRestakedStqtest;
    }

    function previewWithdraw(uint256 rstAmount) public view returns (uint256 stQtestOut) {
        require(rstAmount > 0, "Zero amount");
        uint256 supply = rstqtest.totalSupply();
        require(supply > 0 && totalRestakedStqtest > 0, "Empty vault");
        return (rstAmount * totalRestakedStqtest) / supply;
    }

    function depositStQTEST(uint256 stQtestAmount) external whenNotPaused returns (uint256 rstMinted) {
        rstMinted = previewDeposit(stQtestAmount);
        require(rstMinted > 0, "Zero shares");
        require(stqtest.transferFrom(msg.sender, address(this), stQtestAmount), "stQTEST transfer failed");
        totalRestakedStqtest += stQtestAmount;
        rstqtest.mint(msg.sender, rstMinted);
        emit Deposited(msg.sender, stQtestAmount, rstMinted, exchangeRate());
    }

    function requestWithdraw(uint256 rstAmount) external whenNotPaused returns (uint256 withdrawalId) {
        uint256 stQtestAmount = previewWithdraw(rstAmount);
        require(stQtestAmount > 0, "Zero stQTEST");
        require(stQtestAmount <= totalRestakedStqtest, "Insufficient vault");

        rstqtest.burnFrom(msg.sender, rstAmount);
        totalRestakedStqtest -= stQtestAmount;

        withdrawalId = nextWithdrawalId;
        nextWithdrawalId += 1;

        uint256 availableAt = block.timestamp + cooldownSeconds;
        withdrawals[withdrawalId] = Withdrawal({
            owner: msg.sender,
            rstBurned: rstAmount,
            stQtestAmount: stQtestAmount,
            requestedAt: block.timestamp,
            availableAt: availableAt,
            claimed: false
        });
        _accountWithdrawalIds[msg.sender].push(withdrawalId);

        emit WithdrawRequested(msg.sender, withdrawalId, rstAmount, stQtestAmount, availableAt, exchangeRate());
    }

    function claim(uint256 withdrawalId) external whenNotPaused {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(w.owner == msg.sender, "Not owner");
        require(!w.claimed, "Already claimed");
        require(block.timestamp >= w.availableAt, "Cooldown");
        w.claimed = true;
        require(stqtest.transfer(msg.sender, w.stQtestAmount), "stQTEST transfer failed");
        emit Claimed(msg.sender, withdrawalId, w.stQtestAmount);
    }

    /// @notice Report additional stQTEST rewards into the vault (auto-compound).
    /// @dev Caller must approve stQTEST first. In prod, this is a keeper/guardian action.
    function reportRewards(uint256 stQtestAmount) external onlyGuardianOrOwner {
        require(stQtestAmount > 0, "Zero amount");
        require(stqtest.transferFrom(msg.sender, address(this), stQtestAmount), "stQTEST transfer failed");
        totalRestakedStqtest += stQtestAmount;
        emit RewardsReported(msg.sender, stQtestAmount, totalRestakedStqtest);
    }

    function accountWithdrawalCount(address account) external view returns (uint256) {
        return _accountWithdrawalIds[account].length;
    }

    function accountWithdrawalId(address account, uint256 index) external view returns (uint256) {
        return _accountWithdrawalIds[account][index];
    }

    function recoverToken(address token, address to, uint256 amount) external onlyGuardianOrOwner {
        require(to != address(0), "Invalid to");
        require(token != address(stqtest), "No stQTEST recover");
        require(IERC20Like(token).transfer(to, amount), "Recover failed");
        emit Recovered(token, to, amount);
    }
}

