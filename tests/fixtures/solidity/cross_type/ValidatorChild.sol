pragma solidity ^0.8.0;

import {RewardBase} from "./RewardBase.sol";

contract ValidatorChild is RewardBase {
    function approveValidators() external {
        _collateralize(address(0));
    }
}
