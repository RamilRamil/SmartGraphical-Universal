pragma solidity ^0.8.0;

contract WithdrawNoGuard {
    mapping(address => uint256) internal balances;

    function pull(address to) external {
        uint256 a = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(to).transfer(a);
    }
}
