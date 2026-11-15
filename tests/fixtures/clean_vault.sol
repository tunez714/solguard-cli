// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract CleanStakingVault {
    // Tightly packed into Slot 0 (20B + 8B + 1B = 29B) and Slot 1 (32B)
    address public owner;
    uint64 public epoch;
    bool public paused;
    uint256 public totalStaked;

    // Tightly packed into 1 storage slot (16B + 8B + 8B = 32B)
    struct StakePosition {
        uint128 amount;
        uint64 lockedUntil;
        uint64 rewardDebt;
    }

    mapping(address => StakePosition) public positions;

    // All 3 filterable parameters are indexed
    event Staked(address indexed user, uint256 indexed epoch, uint256 indexed amount);

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        require(!paused, "Paused");
        positions[msg.sender].amount += uint128(msg.value);
        totalStaked += msg.value;
        emit Staked(msg.sender, epoch, msg.value);
    }

    function unstake(uint128 amount) external {
        require(msg.sender == owner || !paused, "Unauthorized");
        require(positions[msg.sender].amount >= amount, "Insufficient stake");

        // Checks-Effects-Interactions: state updated prior to external call
        positions[msg.sender].amount -= amount;
        totalStaked -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    function verifyBatch(bytes32[] calldata leaves) external pure returns (uint256) {
        return leaves.length;
    }
}
