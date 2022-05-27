package com.horizen.account.node;

import com.horizen.account.block.AccountBlock;
import com.horizen.account.transaction.AccountTransaction;
import com.horizen.box.Box;
import com.horizen.node.NodeHistoryBase;
import com.horizen.proof.Proof;
import com.horizen.proposition.Proposition;

import java.util.Optional;

public interface NodeAccountHistory extends NodeHistoryBase {
    Optional<AccountBlock> getBlockById(String blockId);

    AccountBlock getBestBlock();

    Optional<AccountTransaction<Proposition, Proof<Proposition>>> searchTransactionInsideSidechainBlock(String transactionId, String blockId);

    Optional<AccountTransaction<Proposition, Proof<Proposition>>> searchTransactionInsideBlockchain(String transactionId);

}
