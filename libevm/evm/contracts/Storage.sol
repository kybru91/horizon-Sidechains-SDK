// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {

    uint256 number;

    constructor(uint256 initialNumber) {
        number = initialNumber;
    }

    function inc() public {
        number = number + 1;
    }

    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public payable {
        number = num;
    }

    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}