// SPDX-License-Identifier: MIT

pragma solidity 0.8.17;

type StakeID is bytes32;

// contract address: 0000000000000000000022222222222222222222
interface ForgerStakes {

    struct StakeInfo {
        StakeID stakeId;
        uint256 stakedAmount;
        address owner;
        bytes32 publicKey;
        bytes32 vrf1;
        bytes1 vrf2;
    }

    function getAllForgersStakes() external returns (StakeInfo[] memory);

    function delegate(bytes32 publicKey, bytes32 vrf1, bytes1 vrf2, address owner) external payable returns (StakeID);

    function withdraw(bytes32 stakeId, bytes1 signatureA, bytes32 signatureB, bytes32 signatureC) external returns (StakeID);
}
