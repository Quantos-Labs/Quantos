// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SimpleStorage — Minimal contract to validate QuantosVM Solang pipeline
contract SimpleStorage {
    uint256 public storedValue;
    address public owner;

    event ValueSet(address indexed setter, uint256 value);

    constructor(uint256 _initial) {
        storedValue = _initial;
        owner = msg.sender;
        emit ValueSet(msg.sender, _initial);
    }

    function set(uint256 _value) public {
        storedValue = _value;
        emit ValueSet(msg.sender, _value);
    }

    function get() public view returns (uint256) {
        return storedValue;
    }
}
