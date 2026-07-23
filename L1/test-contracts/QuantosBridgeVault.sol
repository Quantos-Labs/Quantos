// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IQTEST {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract QuantosBridgeVault {
    address public token;
    address public owner;
    address public pendingOwner;
    uint256 public baseChainId;
    uint256 public depositNonce;
    bool public paused;

    mapping(bytes32 => bool) public processedReleaseIds;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    event DepositLocked(
        uint256 indexed depositNonce,
        address indexed from,
        bytes32 indexed baseRecipient,
        uint256 amount,
        uint256 baseChainId
    );
    event ReleaseCompleted(bytes32 indexed releaseId, address indexed to, uint256 amount);

    constructor(address tokenAddress, address initialOwner, uint256 targetBaseChainId) {
        require(tokenAddress != address(0), "INVALID_TOKEN");
        require(initialOwner != address(0), "INVALID_OWNER");
        require(targetBaseChainId != 0, "INVALID_BASE_CHAIN");

        token = tokenAddress;
        owner = initialOwner;
        baseChainId = targetBaseChainId;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "PAUSED");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "INVALID_OWNER");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "ONLY_PENDING_OWNER");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function pause() external onlyOwner {
        require(!paused, "ALREADY_PAUSED");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(paused, "NOT_PAUSED");
        paused = false;
        emit Unpaused(msg.sender);
    }

    function deposit(bytes32 baseRecipient, uint256 amount) external whenNotPaused returns (uint256) {
        require(baseRecipient != bytes32(0), "INVALID_RECIPIENT");
        require(amount > 0, "INVALID_AMOUNT");
        require(IQTEST(token).transferFrom(msg.sender, address(this), amount), "TRANSFER_FROM_FAILED");

        uint256 currentNonce = depositNonce;
        depositNonce = currentNonce + 1;

        emit DepositLocked(currentNonce, msg.sender, baseRecipient, amount, baseChainId);
        return currentNonce;
    }

    function release(bytes32 releaseId, address to, uint256 amount) external onlyOwner whenNotPaused returns (bool) {
        require(releaseId != bytes32(0), "INVALID_RELEASE_ID");
        require(!processedReleaseIds[releaseId], "RELEASE_ALREADY_PROCESSED");
        require(to != address(0), "INVALID_RECIPIENT");
        require(amount > 0, "INVALID_AMOUNT");

        processedReleaseIds[releaseId] = true;
        require(IQTEST(token).transfer(to, amount), "TRANSFER_FAILED");

        emit ReleaseCompleted(releaseId, to, amount);
        return true;
    }

    function vaultBalance() external view returns (uint256) {
        return IQTEST(token).balanceOf(address(this));
    }
}
