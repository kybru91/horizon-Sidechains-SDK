package io.horizen.account.state

import io.horizen.SidechainTypes
import io.horizen.account.fork.{Version1_2_0Fork, Version1_4_0Fork}
import io.horizen.account.state.receipt.EthereumReceipt
import io.horizen.account.storage.{AccountStateMetadataStorageView, MsgProcessorMetadataStorageReader}
import io.horizen.account.utils.AccountFeePaymentsUtils.DelegatorFeePayment
import io.horizen.account.utils._
import io.horizen.block.{MainchainBlockReferenceData, WithdrawalEpochCertificate}
import io.horizen.consensus.ConsensusEpochNumber
import io.horizen.evm.StateDB
import io.horizen.state.StateView
import io.horizen.utils.WithdrawalEpochInfo
import sparkz.core.VersionTag
import sparkz.util.{ModifierId, SparkzLogging}

import java.math.BigInteger

// this class extends 2 main hierarchies, which are kept separate:
//  - StateView (trait): metadata read/write
//      Implements the methods via metadataStorageView
//  - StateDbAccountStateView (concrete class) : evm stateDb read/write
//      Inherits its methods
class AccountStateView(
  metadataStorageView: AccountStateMetadataStorageView,
  stateDb: StateDB,
  messageProcessors: Seq[MessageProcessor],
) extends StateDbAccountStateView(stateDb, messageProcessors)
    with MsgProcessorMetadataStorageReader
    with StateView[SidechainTypes#SCAT]
    with SparkzLogging {

  def addTopQualityCertificates(refData: MainchainBlockReferenceData, blockId: ModifierId): Unit = {
    refData.topQualityCertificate.foreach(cert => {
      log.debug(s"adding top quality cert to state: $cert.")
      updateTopQualityCertificate(cert, blockId)
    })
  }

  // out-of-the-box helpers
  override def updateTopQualityCertificate(cert: WithdrawalEpochCertificate, blockId: ModifierId): Unit = {
    metadataStorageView.updateTopQualityCertificate(cert)
    metadataStorageView.updateLastCertificateReferencedEpoch(cert.epochNumber)
    metadataStorageView.updateLastCertificateSidechainBlockIdOpt(blockId)
  }

  override def updateFeePaymentInfo(info: AccountBlockFeeInfo): Unit = {
    metadataStorageView.updateFeePaymentInfo(info)
  }

  override def updateWithdrawalEpochInfo(withdrawalEpochInfo: WithdrawalEpochInfo): Unit =
    metadataStorageView.updateWithdrawalEpochInfo(withdrawalEpochInfo)

  override def updateConsensusEpochNumber(consensusEpochNum: ConsensusEpochNumber): Unit =
    metadataStorageView.updateConsensusEpochNumber(consensusEpochNum)

  override def updateTransactionReceipts(receipts: Seq[EthereumReceipt]): Unit =
    metadataStorageView.updateTransactionReceipts(receipts)

  def getTransactionReceipt(txHash: Array[Byte]): Option[EthereumReceipt] =
    metadataStorageView.getTransactionReceipt(txHash)

  def updateNextBaseFee(baseFee: BigInteger): Unit = metadataStorageView.updateNextBaseFee(baseFee)

  def getNextBaseFee: BigInteger = metadataStorageView.getNextBaseFee

  override def setCeased(): Unit = metadataStorageView.setCeased()

  override def commit(version: VersionTag): Unit = {
    // Update StateDB without version, then set the rootHash and commit metadataStorageView
    val rootHash = stateDb.commit()
    metadataStorageView.updateAccountStateRoot(rootHash.toBytes)
    metadataStorageView.commit(version)
  }

  override def getTopQualityCertificate(referencedWithdrawalEpoch: Int): Option[WithdrawalEpochCertificate] =
    metadataStorageView.getTopQualityCertificate(referencedWithdrawalEpoch)

  override def getWithdrawalEpochInfo: WithdrawalEpochInfo = metadataStorageView.getWithdrawalEpochInfo

  override def hasCeased: Boolean = metadataStorageView.hasCeased

  override def getConsensusEpochNumber: Option[ConsensusEpochNumber] = metadataStorageView.getConsensusEpochNumber

  // useful in bootstrapping tool
  def getConsensusEpochNumberAsInt: Int = getConsensusEpochNumber.getOrElse(0)

  // after this we always reset the counters
  override def getFeePaymentsInfo(
    withdrawalEpoch: Int,
    consensusEpochNumber: ConsensusEpochNumber,
    distributionCap: BigInteger,
    blockToAppendFeeInfo: Option[AccountBlockFeeInfo] = None,
  ): (Seq[AccountPayment], BigInteger) = {
    var blockFeeInfoSeq = metadataStorageView.getFeePayments(withdrawalEpoch)
    blockToAppendFeeInfo.foreach(blockFeeInfo => blockFeeInfoSeq = blockFeeInfoSeq :+ blockFeeInfo)
    val mcForgerPoolRewards = getMcForgerPoolRewards(consensusEpochNumber, distributionCap)
    val poolBalanceDistributed = mcForgerPoolRewards.values.foldLeft(BigInteger.ZERO)((a, b) => a.add(b))
    metadataStorageView.updateMcForgerPoolRewards(mcForgerPoolRewards)
    if (Version1_4_0Fork.get(consensusEpochNumber).active) {
      val forgerRewards = AccountFeePaymentsUtils.getForgersRewards(blockFeeInfoSeq, mcForgerPoolRewards)
      val (forgerPayments, delegatorPayments) = getForgersAndDelegatorsShares(forgerRewards)
      metadataStorageView.updateForgerDelegatorPayments(delegatorPayments, consensusEpochNumber)

      val allPayments = AccountFeePaymentsUtils.groupAllPaymentsByAddress(forgerPayments, delegatorPayments)

      (allPayments, poolBalanceDistributed)
    } else {
      val payments = AccountFeePaymentsUtils.getForgersRewards(blockFeeInfoSeq, mcForgerPoolRewards)
          .map(fp => AccountPayment(fp.identifier.address, fp.value))
      (payments, poolBalanceDistributed)
    }
  }

  private[horizen] def getForgersAndDelegatorsShares(feePayments: Seq[ForgerPayment]): (Seq[AccountPayment], Seq[DelegatorFeePayment]) = {
    val allPayments = feePayments.map { feePayment =>
      Some(feePayment)
        // after fork 1.4 blockSignPublicKey and vrfPublicKey are mandatory
        .filter(_.identifier.blockSignPublicKey.isDefined).filter(_.identifier.vrfPublicKey.isDefined)
        // try get ForgerInfo from StakeStorageV2
        .flatMap(fp => getForgerInfo(ForgerPublicKeys(fp.identifier.blockSignPublicKey.get, fp.identifier.vrfPublicKey.get)))
        // split reward into forger and delegator shares
        .map(info => AccountFeePaymentsUtils.getForgerAndDelegatorShares(feePayment, info))
        // for blocks <1.4 fork all reward goes to forger
        .getOrElse {
          val totalFeeReward = feePayment.value.subtract(feePayment.valueFromMainchain)
          val forgerPayment = AccountPayment(feePayment.identifier.address, feePayment.value, Some(feePayment.valueFromMainchain), Some(totalFeeReward))
          (forgerPayment, None)
        }
    }
    // this is to collapse delegator payments into a flat list. Also null payments are filtered out.
    (allPayments.withFilter(_._1.value.signum()==1).map(_._1), allPayments.flatMap(_._2))
  }

  override def getAccountStateRoot: Array[Byte] = metadataStorageView.getAccountStateRoot

  override def getForgerRewards(
    forgerPublicKeys: ForgerPublicKeys,
    consensusEpochStart: Int,
    maxNumOfEpochs: Int,
  ): Seq[BigInteger] = {
    metadataStorageView.getForgerRewards(forgerPublicKeys, consensusEpochStart, maxNumOfEpochs)
  }

  def getMcForgerPoolRewards(
    consensusEpochNumber: ConsensusEpochNumber,
    distributionCap: BigInteger,
  ): Map[ForgerIdentifier, BigInteger] = {
    if (Version1_2_0Fork.get(consensusEpochNumber).active) {
      val extraForgerReward = getBalance(WellKnownAddresses.FORGER_POOL_RECIPIENT_ADDRESS)
      if (extraForgerReward.signum() == 1) {
        val availableReward = extraForgerReward.min(distributionCap)
        val counters: Map[ForgerIdentifier, Long] = getForgerBlockCounters
        val perBlockFee_remainder = availableReward.divideAndRemainder(BigInteger.valueOf(counters.values.sum))
        val perBlockFee = perBlockFee_remainder(0)
        var remainder = perBlockFee_remainder(1)
        //sort and add remainder based by block count
        val forgerPoolRewards = counters.toSeq
          .sortBy(_._2)
          .map { address_blocks =>
            val blocks = BigInteger.valueOf(address_blocks._2)
            val usedRemainder = remainder.min(blocks)
            val reward = perBlockFee.multiply(blocks).add(usedRemainder)
            remainder = remainder.subtract(usedRemainder)
            (address_blocks._1, reward)
          }
        forgerPoolRewards.toMap
      } else Map.empty
    } else Map.empty
  }

  def updateForgerBlockCounter(forgerKey: ForgerIdentifier, consensusEpochNumber: ConsensusEpochNumber): Unit = {
    if (Version1_2_0Fork.get(consensusEpochNumber).active) {
      metadataStorageView.updateForgerBlockCounter(forgerKey)
    }
  }

  def getForgerBlockCounters: Map[ForgerIdentifier, Long] = {
    metadataStorageView.getForgerBlockCounters
  }

  def subtractForgerPoolBalanceAndResetBlockCounters(
    consensusEpochNumber: ConsensusEpochNumber,
    poolBalanceDistributed: BigInteger,
  ): Unit = {
    if (Version1_2_0Fork.get(consensusEpochNumber).active) {
      val forgerPoolBalance = getBalance(WellKnownAddresses.FORGER_POOL_RECIPIENT_ADDRESS)
      if (poolBalanceDistributed.compareTo(forgerPoolBalance) > 0) {
        val errMsg =
          s"Trying to subtract more($poolBalanceDistributed) from the forger pool balance than available($forgerPoolBalance)"
        log.error(errMsg)
        throw new IllegalArgumentException(errMsg)
      }
      if (forgerPoolBalance.signum() == 1) {
        subBalance(WellKnownAddresses.FORGER_POOL_RECIPIENT_ADDRESS, poolBalanceDistributed)
        metadataStorageView.resetForgerBlockCounters()
      }
    }
  }
}
