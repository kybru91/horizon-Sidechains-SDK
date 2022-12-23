package com.horizen.node;

import com.horizen.box.Box;
import com.horizen.proposition.Proposition;
import com.horizen.transaction.BoxTransaction;

import java.util.List;

public interface NodeMemoryPool extends NodeMemoryPoolBase<BoxTransaction<Proposition, Box<Proposition>>>{
    /**
     * Get transactions sorted by fee, from the lowest one in ascending order
     * @deprecated use {@link #getTransactionsSortedByFeeRate(int)} instead (note that the order will be the opposite there)
     */
    @Deprecated
    List<BoxTransaction<Proposition, Box<Proposition>>> getTransactionsSortedByFee(int limit);

    /**
     * Get transactions sorted by feeRate, from the highest one in descending order
     */
    List<BoxTransaction<Proposition, Box<Proposition>>> getTransactionsSortedByFeeRate(int limit);
}
