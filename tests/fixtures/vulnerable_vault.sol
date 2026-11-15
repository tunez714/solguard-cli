// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposited(address indexed account, uint256 indexed amount, uint256 indexed timestamp);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value, block.timestamp);
    }

    // Triggers SG001 (unchecked call) and SG002 (state write after external call)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // Triggers SG003 (tx.origin authorization) and SG001 (unchecked send)
    function emergencySweep(address payable recipient, uint256 amount) external {
        require(tx.origin == owner, "Not authorized");
        recipient.send(amount);
    }
}
