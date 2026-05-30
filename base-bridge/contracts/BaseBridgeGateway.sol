pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IWrappedQTEST {
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

error ZeroAddress();
error InvalidAmount();
error InvalidId();
error InvalidRecipient();
error Unauthorized();
error DepositAlreadyProcessed();

contract BaseBridgeGateway is Ownable2Step, Pausable, ReentrancyGuard {
    IWrappedQTEST public immutable wrappedToken;
    uint256 public immutable quantosChainId;
    uint256 public burnNonce;

    mapping(address => bool) public relayers;
    mapping(bytes32 => bool) public processedQuantosDeposits;

    event RelayerUpdated(address indexed relayer, bool allowed);
    event QuantosDepositMinted(
        bytes32 indexed quantosDepositId,
        uint256 indexed quantosDepositNonce,
        address indexed recipient,
        uint256 amount,
        bytes32 quantosSender
    );
    event BaseBurnInitiated(
        uint256 indexed burnNonce,
        address indexed from,
        bytes32 indexed quantosRecipient,
        uint256 amount,
        uint256 quantosChainId
    );

    constructor(address wrappedTokenAddress, address initialOwner, uint256 targetQuantosChainId)
        Ownable(initialOwner)
    {
        if (wrappedTokenAddress == address(0) || initialOwner == address(0)) revert ZeroAddress();
        if (targetQuantosChainId == 0) revert InvalidId();
        wrappedToken = IWrappedQTEST(wrappedTokenAddress);
        quantosChainId = targetQuantosChainId;
    }

    modifier onlyRelayer() {
        if (!relayers[msg.sender]) revert Unauthorized();
        _;
    }

    function setRelayer(address relayer, bool allowed) external onlyOwner {
        if (relayer == address(0)) revert ZeroAddress();
        relayers[relayer] = allowed;
        emit RelayerUpdated(relayer, allowed);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function mintFromQuantos(
        bytes32 quantosDepositId,
        uint256 quantosDepositNonce,
        bytes32 quantosSender,
        address recipient,
        uint256 amount
    ) external onlyRelayer whenNotPaused nonReentrant {
        if (quantosDepositId == bytes32(0)) revert InvalidId();
        if (recipient == address(0) || quantosSender == bytes32(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (processedQuantosDeposits[quantosDepositId]) revert DepositAlreadyProcessed();

        processedQuantosDeposits[quantosDepositId] = true;
        wrappedToken.mint(recipient, amount);

        emit QuantosDepositMinted(
            quantosDepositId,
            quantosDepositNonce,
            recipient,
            amount,
            quantosSender
        );
    }

    function burnToQuantos(bytes32 quantosRecipient, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        if (quantosRecipient == bytes32(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();

        uint256 currentBurnNonce = burnNonce;
        burnNonce = currentBurnNonce + 1;

        wrappedToken.burnFrom(msg.sender, amount);

        emit BaseBurnInitiated(currentBurnNonce, msg.sender, quantosRecipient, amount, quantosChainId);
        return currentBurnNonce;
    }
}
