pragma solidity ^0.8.22;

library ExitQueue {
    struct History {
        uint256 head;
        uint256 tail;
    }
}

abstract contract VaultState {
    uint256 internal _donatedAssets;
    uint128 internal _totalShares;
    uint64 internal _capacity;
    uint32 internal _epoch;
    mapping(address => uint256) internal _balances;
    mapping(address => uint256) internal _exitRequests;
    mapping(address => bool) internal _paused;
    ExitQueue.History internal _exitQueue;
    bytes32 internal _root;
    address internal _admin;
}
