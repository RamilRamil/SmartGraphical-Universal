pragma solidity ^0.8.0;

abstract contract ERC20Upgradeable {
    function _mint(address to, uint256 amount) internal virtual;
}
