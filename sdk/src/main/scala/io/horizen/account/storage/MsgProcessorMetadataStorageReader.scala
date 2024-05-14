package io.horizen.account.storage

import io.horizen.account.state.ForgerPublicKeys

import java.math.BigInteger

// minimal reader interface to access metadata storage from native smart contracts
trait MsgProcessorMetadataStorageReader {
  def getForgerRewards(
    forgerPublicKeys: ForgerPublicKeys,
    consensusEpochStart: Int,
    maxNumOfEpochs: Int,
  ): Seq[BigInteger]
}
