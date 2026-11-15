// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GasInefficientRegistry {
    // Suboptimal state variable ordering: bool (1B) + uint256 (32B) + address (20B) + uint64 (8B)
    // Uses 3 slots sequentially, but fits in 2 slots when packed.
    bool public paused;
    uint256 public protocolFeeBps;
    address public treasury;
    uint64 public epoch;

    // Suboptimal struct ordering: uses 3 slots sequentially, but fits in 2 slots.
    struct OrderRecord {
        uint8 status;
        uint256 amount;
        address maker;
        bool settled;
    }

    // Triggers SG004: 0 indexed parameters out of 3 filterable value parameters
    event OrderRegistered(address maker, uint256 orderId, uint256 amount);

    mapping(uint256 => OrderRecord) public orders;

    // Triggers SG005: `batchTag` and `orderIds` are read-only reference params using `memory`
    function registerBatch(
        string memory batchTag,
        uint256[] memory orderIds,
        uint256 amount
    ) external returns (uint256 count) {
        require(!paused, batchTag);
        count = orderIds.length;
        if (count > 0) {
            uint256 firstId = orderIds[0];
            orders[firstId] = OrderRecord({
                status: 1,
                amount: amount,
                maker: msg.sender,
                settled: false
            });
            emit OrderRegistered(msg.sender, firstId, amount);
        }
    }
}
