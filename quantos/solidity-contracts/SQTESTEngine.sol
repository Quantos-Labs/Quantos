// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISQTEST {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

interface IQTEST {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title SQTESTEngine - Vault and stability engine for SQTEST stablecoin
/// @notice Manages vaults with QTEST collateral, annual stability fees, lazy accrual
contract SQTESTEngine {
    ISQTEST public immutable sqtest;
    IQTEST public immutable qtest;
    
    uint256 public constant COLLATERAL_RATIO = 150; // 150% collateralization
    uint256 public constant LIQUIDATION_THRESHOLD = 120; // 120% liquidation threshold
    uint256 public constant LIQUIDATION_PENALTY = 10; // 10% penalty
    uint256 public stabilityFeeBps = 500; // 5% annual fee (500 basis points)
    uint256 public constant SECONDS_PER_YEAR = 365 days;

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }
    
    struct Vault {
        uint256 collateralAmount;
        uint256 debtAmount;
        uint256 lastAccrualTime;
    }
    
    mapping(address => Vault) public vaults;
    
    event VaultOpened(address indexed user, uint256 collateral, uint256 debt);
    event CollateralDeposited(address indexed user, uint256 amount);
    event DebtMinted(address indexed user, uint256 amount);
    event DebtRepaid(address indexed user, uint256 amount);
    event CollateralWithdrawn(address indexed user, uint256 amount);
    event VaultLiquidated(address indexed user, address indexed liquidator, uint256 collateralSeized, uint256 debtRepaid);
    event StabilityFeeUpdated(uint256 newFeeBps);
    
    constructor(address _sqtest, address _qtest) {
        require(_sqtest != address(0) && _qtest != address(0), "Invalid addresses");
        sqtest = ISQTEST(_sqtest);
        qtest = IQTEST(_qtest);
    }
    
    function openVault(uint256 collateralAmount, uint256 debtAmount) external {
        require(vaults[msg.sender].collateralAmount == 0, "Vault exists");
        require(collateralAmount > 0 && debtAmount > 0, "Invalid amounts");
        require(_isHealthy(collateralAmount, debtAmount), "Undercollateralized");
        
        require(qtest.transferFrom(msg.sender, address(this), collateralAmount), "Transfer failed");
        
        vaults[msg.sender] = Vault({
            collateralAmount: collateralAmount,
            debtAmount: debtAmount,
            lastAccrualTime: block.timestamp
        });
        
        sqtest.mint(msg.sender, debtAmount);
        emit VaultOpened(msg.sender, collateralAmount, debtAmount);
    }
    
    function depositCollateral(uint256 amount) external {
        require(vaults[msg.sender].collateralAmount > 0, "No vault");
        require(amount > 0, "Invalid amount");
        
        _accrueInterest(msg.sender);
        
        require(qtest.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        vaults[msg.sender].collateralAmount += amount;
        
        emit CollateralDeposited(msg.sender, amount);
    }
    
    function mintDebt(uint256 amount) external {
        require(vaults[msg.sender].collateralAmount > 0, "No vault");
        require(amount > 0, "Invalid amount");
        
        _accrueInterest(msg.sender);
        
        Vault storage vault = vaults[msg.sender];
        uint256 newDebt = vault.debtAmount + amount;
        require(_isHealthy(vault.collateralAmount, newDebt), "Undercollateralized");
        
        vault.debtAmount = newDebt;
        sqtest.mint(msg.sender, amount);
        
        emit DebtMinted(msg.sender, amount);
    }
    
    function repayDebt(uint256 amount) external {
        require(vaults[msg.sender].collateralAmount > 0, "No vault");
        require(amount > 0, "Invalid amount");
        
        _accrueInterest(msg.sender);
        
        Vault storage vault = vaults[msg.sender];
        require(amount <= vault.debtAmount, "Exceeds debt");
        
        sqtest.burn(msg.sender, amount);
        vault.debtAmount -= amount;
        
        emit DebtRepaid(msg.sender, amount);
    }
    
    function withdrawCollateral(uint256 amount) external {
        require(vaults[msg.sender].collateralAmount > 0, "No vault");
        require(amount > 0, "Invalid amount");
        
        _accrueInterest(msg.sender);
        
        Vault storage vault = vaults[msg.sender];
        require(amount <= vault.collateralAmount, "Exceeds collateral");
        
        uint256 newCollateral = vault.collateralAmount - amount;
        if (vault.debtAmount > 0) {
            require(_isHealthy(newCollateral, vault.debtAmount), "Undercollateralized");
        }
        
        vault.collateralAmount = newCollateral;
        require(qtest.transfer(msg.sender, amount), "Transfer failed");
        
        emit CollateralWithdrawn(msg.sender, amount);
    }
    
    function liquidate(address user) external {
        require(vaults[user].collateralAmount > 0, "No vault");
        
        _accrueInterest(user);
        
        Vault storage vault = vaults[user];
        require(!_isHealthyLiquidation(vault.collateralAmount, vault.debtAmount), "Vault healthy");
        
        uint256 debtToRepay = vault.debtAmount;
        uint256 collateralToSeize = vault.collateralAmount;
        uint256 penalty = _div(_mul(collateralToSeize, LIQUIDATION_PENALTY), 100);
        uint256 liquidatorReward = collateralToSeize - penalty;
        
        sqtest.burn(msg.sender, debtToRepay);
        
        vault.collateralAmount = 0;
        vault.debtAmount = 0;
        
        require(qtest.transfer(msg.sender, liquidatorReward), "Transfer failed");
        
        emit VaultLiquidated(user, msg.sender, collateralToSeize, debtToRepay);
    }
    
    function getVaultHealth(address user) external view returns (uint256) {
        Vault memory vault = vaults[user];
        if (vault.debtAmount == 0) return type(uint256).max;
        
        uint256 accruedDebt = _calculateAccruedDebt(vault.debtAmount, vault.lastAccrualTime);
        return _div(_mul(vault.collateralAmount, 100), accruedDebt);
    }
    
    function getAccruedDebt(address user) external view returns (uint256) {
        Vault memory vault = vaults[user];
        return _calculateAccruedDebt(vault.debtAmount, vault.lastAccrualTime);
    }
    
    function _accrueInterest(address user) private {
        Vault storage vault = vaults[user];
        if (vault.debtAmount == 0) return;
        
        uint256 accruedDebt = _calculateAccruedDebt(vault.debtAmount, vault.lastAccrualTime);
        vault.debtAmount = accruedDebt;
        vault.lastAccrualTime = block.timestamp;
    }
    
    function _calculateAccruedDebt(uint256 principal, uint256 lastTime) private view returns (uint256) {
        if (principal == 0) return 0;

        if (lastTime == 0 || block.timestamp <= lastTime) {
            return principal;
        }

        uint256 timeElapsed = block.timestamp - lastTime;
        if (timeElapsed == 0) return principal;
        
        uint256 feeAccrued = _div(_mul(_mul(principal, stabilityFeeBps), timeElapsed), _mul(10000, SECONDS_PER_YEAR));
        return principal + feeAccrued;
    }
    
    function _isHealthy(uint256 collateral, uint256 debt) private view returns (bool) {
        if (debt == 0) return true;
        return _div(_mul(collateral, 100), debt) >= COLLATERAL_RATIO;
    }
    
    function _isHealthyLiquidation(uint256 collateral, uint256 debt) private view returns (bool) {
        if (debt == 0) return true;
        return _div(_mul(collateral, 100), debt) >= LIQUIDATION_THRESHOLD;
    }
}
