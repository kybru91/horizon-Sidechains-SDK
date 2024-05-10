package io.horizen.account.utils

import io.horizen.account.network.ForgerInfo
import io.horizen.account.state.{ForgerPublicKeys, ForgerStakeV2MsgProcessor}
import io.horizen.evm.{StateDB, TrieHasher}
import io.horizen.params.NetworkParams

import java.math.BigInteger

object AccountFeePaymentsUtils {
  val DEFAULT_ACCOUNT_FEE_PAYMENTS_HASH: Array[Byte] = StateDB.EMPTY_ROOT_HASH.toBytes
  val MC_DISTRIBUTION_CAP_DIVIDER: BigInteger = BigInteger.valueOf(10)
  val TOTAL_SHARE: BigInteger = BigInteger.valueOf(ForgerStakeV2MsgProcessor.MAX_REWARD_SHARE)

  def calculateFeePaymentsHash(feePayments: Seq[AccountPayment]): Array[Byte] = {
    if (feePayments.isEmpty) {
      // No fees for the whole epoch, so no fee payments for the Forgers.
      DEFAULT_ACCOUNT_FEE_PAYMENTS_HASH
    } else {
      // turn seq elements into leaves and compute merkel root hash
      TrieHasher.Root(feePayments.map(payment => payment.bytes).toArray).toBytes
    }
  }

  def getForgersRewards(
    blockFeeInfoSeq: Seq[AccountBlockFeeInfo],
    mcForgerPoolRewards: Map[ForgerIdentifier, BigInteger] = Map.empty,
  ): Seq[ForgerPayment] = {
    if (blockFeeInfoSeq.isEmpty)
      return mcForgerPoolRewards.map(reward => ForgerPayment(reward._1, reward._2)).toSeq

    var poolFee: BigInteger = BigInteger.ZERO
    val forgersBlockRewards: Seq[ForgerPayment] = blockFeeInfoSeq.map(feeInfo => {
      poolFee = poolFee.add(feeInfo.baseFee)
      val forgerIdentifier = ForgerIdentifier(feeInfo.forgerAddress, feeInfo.blockSignPublicKey, feeInfo.vrfPublicKey)
      ForgerPayment(forgerIdentifier, feeInfo.forgerTips)
    })

    // Split poolFee in equal parts to be paid to forgers.
    val divAndRem: Array[BigInteger] = poolFee.divideAndRemainder(BigInteger.valueOf(forgersBlockRewards.size))
    val forgerPoolFee: BigInteger = divAndRem(0)
    // The rest N satoshis must be paid to the first N forgers (1 satoshi each)
    val rest: Long = divAndRem(1).longValueExact()

    // Calculate final fee for forger considering forger fee, pool fee and the undistributed satoshis
    val allForgersRewards: Seq[ForgerPayment] = forgersBlockRewards.zipWithIndex.map {
      case (forgerBlockReward: ForgerPayment, index: Int) =>
        val finalForgerFee =
          forgerBlockReward.value.add(forgerPoolFee).add(if (index < rest) BigInteger.ONE else BigInteger.ZERO)
        ForgerPayment(forgerBlockReward.identifier, finalForgerFee)
    }

    // Get all unique forger addresses
    val forgerKeys: Seq[ForgerIdentifier] = (allForgersRewards.map(_.identifier) ++ mcForgerPoolRewards.keys).distinct

    // sum all rewards for per forger address
    forgerKeys.map { forgerKey =>
      val forgerTotalFee = allForgersRewards
        .filter(info => forgerKey.equals(info.identifier))
        .foldLeft(BigInteger.ZERO)((sum, info) => sum.add(info.value))
      // add mcForgerPoolReward if exists
      val mcForgerPoolReward = mcForgerPoolRewards.getOrElse(forgerKey, BigInteger.ZERO)
      // return the resulting entry
      ForgerPayment(forgerKey, forgerTotalFee.add(mcForgerPoolReward))
    }
  }

  def getForgerAndDelegatorShares(
    mcForgerPoolRewards: Map[ForgerIdentifier, BigInteger],
    feePayment: ForgerPayment,
    forgerInfo: ForgerInfo,
  ): (AccountPayment, Option[DelegatorFeePayment]) = {
    val rewardAddress = feePayment.identifier.address
    val delegatorShare = BigInteger.valueOf(forgerInfo.rewardShare)
    val totalMcReward = mcForgerPoolRewards.getOrElse(feePayment.identifier, BigInteger.ZERO)

    if (delegatorShare.compareTo(BigInteger.ZERO) == 0) {
      // No delegator share, all reward goes to the forger
      val totalFeeReward = feePayment.value.subtract(totalMcReward)
      val forgerPayment = AccountPayment(rewardAddress, feePayment.value, Some(totalMcReward), Some(totalFeeReward))
      return (forgerPayment, None)
    }

    val delegatorReward = feePayment.value.multiply(delegatorShare).divide(TOTAL_SHARE)
    val delegatorMcReward = totalMcReward.multiply(delegatorShare).divide(TOTAL_SHARE)
    val delegatorFeeReward = delegatorReward.subtract(delegatorMcReward)

    val forgerReward = feePayment.value.subtract(delegatorReward)
    val forgerMcReward = totalMcReward.subtract(delegatorMcReward)
    val forgerFeeReward = forgerReward.subtract(forgerMcReward)

    val forgerPayment = AccountPayment(rewardAddress, forgerReward, Some(forgerMcReward), Some(forgerFeeReward))
    val delegatorPayment = DelegatorFeePayment(
      AccountPayment(forgerInfo.rewardAddress, delegatorReward, Some(delegatorMcReward), Some(delegatorFeeReward)),
      forgerInfo.forgerPublicKeys,
    )
    (forgerPayment, Some(delegatorPayment))
  }

  def groupAllPaymentsByAddress(
    feePayments: Seq[AccountPayment],
    delegatorPayments: Seq[DelegatorFeePayment],
  ): Seq[AccountPayment] = {
    (feePayments ++ delegatorPayments.map(_.feePayment))
      .groupBy(_.address)
      .map { case (address, payments) =>
        AccountPayment(
          address,
          payments.map(_.value).foldLeft(BigInteger.ZERO)((a, b) => a.add(b)),
          Some(payments.map(_.valueFromMainchain).foldLeft(BigInteger.ZERO)((a, b) => a.add(b.getOrElse(BigInteger.ZERO)))),
          Some(payments.map(_.valueFromFees).foldLeft(BigInteger.ZERO)((a, b) => a.add(b.getOrElse(BigInteger.ZERO)))),
        )
      }.toSeq
  }

  def getMainchainWithdrawalEpochDistributionCap(epochMaxHeight: Long, params: NetworkParams): BigInteger = {
    val baseReward = 12.5 * 1e8
    val halvingInterval = params.mcHalvingInterval
    val epochLength = params.withdrawalEpochLength

    var mcEpochRewardZennies = 0L
    for (height <- epochMaxHeight - epochLength until epochMaxHeight) {
      var reward = baseReward.longValue()
      val halvings = height / halvingInterval
      for (_ <- 1L to halvings) {
        reward = reward >> 1
      }
      mcEpochRewardZennies = mcEpochRewardZennies + reward
    }

    val mcEpochRewardWei = ZenWeiConverter.convertZenniesToWei(mcEpochRewardZennies)
    mcEpochRewardWei.divide(getMcDistributionCapDivider)
  }

  private def getMcDistributionCapDivider: BigInteger = MC_DISTRIBUTION_CAP_DIVIDER

  case class DelegatorFeePayment(feePayment: AccountPayment, forgerKeys: ForgerPublicKeys)
}
