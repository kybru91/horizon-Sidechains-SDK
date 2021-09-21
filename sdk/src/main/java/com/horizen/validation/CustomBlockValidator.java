package com.horizen.validation;

import com.horizen.block.SidechainBlock;
import com.horizen.node.NodeHistory;

public interface CustomBlockValidator {
    /*
     * Define custom validation rules for the Block when is applied to the History.
     *
     * Method may throw one of the following exceptions which have an impact on the ban strategy:
     * @InvalidBlockCustomValidatorException - if block is totally invalid. The block and the sender will be banned.
     * @InconsistentDataCustomValidatorException - if block contains valid main/header part, but inconsistent data. So ban the sender only.
     * @BlockInFutureCustomValidatorException - if block is not in time. Don't ban sender and block. Let retrieve the block later.
     */
    void validate(SidechainBlock block, NodeHistory nodeHistory)
            throws BlockInFutureCustomValidatorException, InconsistentDataCustomValidatorException, InvalidBlockCustomValidatorException;
}
