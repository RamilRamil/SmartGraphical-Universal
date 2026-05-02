pragma solidity ^0.8.0;

contract ExternalMint {
    mapping(address => uint256) internal balances;

    function mint(address to, uint256 v) external {
        balances[to] += v;
    }
}
