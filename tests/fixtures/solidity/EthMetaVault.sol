pragma solidity ^0.8.0;

import {ISample} from "./SampleInterface.sol";
import {ExternalMint} from "./ExternalMint.sol";

contract EthMetaVault {
    uint256 public total;

    function deposit() public {
        total += 1;
    }

    function updateStateAndDeposit() public {
        deposit();
    }

    function foo() external view override(ISample) returns (uint256) {
        return total;
    }
}
