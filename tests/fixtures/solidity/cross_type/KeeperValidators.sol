pragma solidity ^0.8.0;

import {KeeperRewards} from "./KeeperRewards.sol";

contract KeeperValidators is KeeperRewards {
    function approveValidators() external {
        _collateralize(address(0));
    }
}
