pragma solidity ^0.8.0;

contract MixedMath {
    function mix(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        uint256 x = a * b / c;
        return x;
    }
}
