// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

struct Reward {
    uint64 nonce;
    uint256 assets;
}

contract KeeperRewardsStateAccessFixture {
    mapping(address => Reward) public rewards;
    uint64 public rewardsNonce;
    bytes32 public rewardsRoot;

    function isCollateralized(address vault) public view returns (bool) {
        return rewards[vault].nonce != 0;
    }

    function canHarvest(address vault) external view returns (bool) {
        uint256 nonce = rewards[vault].nonce;
        return nonce != 0 && nonce < rewardsNonce;
    }

    function isHarvestRequired(address vault) external view returns (bool) {
        uint256 nonce = rewards[vault].nonce;
        unchecked {
            return nonce != 0 && nonce + 1 < rewardsNonce;
        }
    }

    function updateRewards() external {
        rewardsRoot = bytes32(uint256(1));
        unchecked {
            rewardsNonce = rewardsNonce + 1;
        }
    }

    function harvest(address vault, uint256 reward) external {
        Reward storage lastReward = rewards[vault];
        if (lastReward.nonce >= rewardsNonce) {
            return;
        }
        lastReward.nonce = rewardsNonce;
        lastReward.assets = reward;
    }

    function _collateralize(address vault) internal {
        if (rewards[vault].nonce != 0) {
            return;
        }
        rewards[vault] = Reward({nonce: rewardsNonce, assets: 0});
    }
}
