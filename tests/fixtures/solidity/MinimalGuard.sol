pragma solidity ^0.8.0;

contract MinimalGuard {
    uint256 public amount;

    function setAmount(uint256 v) external {
        require(v > 0, "min");
        amount = v;
    }
}
