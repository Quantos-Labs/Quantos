// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

error ZeroAddress();
error Unauthorized();

contract WrappedQTEST is ERC20, Ownable2Step {
    address public bridgeGateway;

    event BridgeGatewayUpdated(address indexed previousGateway, address indexed newGateway);

    constructor(address initialOwner)
        ERC20("Wrapped Quantos Test Token", "wQTEST")
        Ownable(initialOwner)
    {
        if (initialOwner == address(0)) revert ZeroAddress();
    }

    modifier onlyBridgeGateway() {
        if (msg.sender != bridgeGateway) revert Unauthorized();
        _;
    }

    function setBridgeGateway(address newGateway) external onlyOwner {
        if (newGateway == address(0)) revert ZeroAddress();
        address previousGateway = bridgeGateway;
        bridgeGateway = newGateway;
        emit BridgeGatewayUpdated(previousGateway, newGateway);
    }

    function mint(address to, uint256 amount) external onlyBridgeGateway {
        if (to == address(0)) revert ZeroAddress();
        _mint(to, amount);
    }

    function burnFrom(address from, uint256 amount) external onlyBridgeGateway {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
    }
}
