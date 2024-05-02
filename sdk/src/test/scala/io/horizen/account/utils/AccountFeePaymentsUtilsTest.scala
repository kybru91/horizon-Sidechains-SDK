package io.horizen.account.utils

import io.horizen.account.network.ForgerInfo
import io.horizen.account.proposition.AddressProposition
import io.horizen.account.secret.PrivateKeySecp256k1Creator
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.account.utils.AccountFeePaymentsUtils.{getForgerAndDelegatorShares, getForgersRewards, getMainchainWithdrawalEpochDistributionCap}
import io.horizen.fixtures._
import io.horizen.params.MainNetParams
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.utils.BytesUtils
import org.junit.Assert._
import org.junit._
import org.scalatestplus.junit.JUnitSuite
import org.scalatestplus.mockito._

import java.math.BigInteger
import java.nio.charset.StandardCharsets


class AccountFeePaymentsUtilsTest
  extends JUnitSuite
    with SidechainRelatedMainchainOutputFixture
    with MockitoSugar
{
  val addr_a: Array[Byte] = BytesUtils.fromHexString("00000000000000000000000000000000000000aa")
  val addr_b: Array[Byte] = BytesUtils.fromHexString("00000000000000000000000000000000000000bb")
  val addr_c: Array[Byte] = BytesUtils.fromHexString("00000000000000000000000000000000000000cc")
  val addr_d: Array[Byte] = BytesUtils.fromHexString("00000000000000000000000000000000000000dd")
  val forgerAddr_a = new AddressProposition(addr_a)
  val forgerAddr_b = new AddressProposition(addr_b)
  val forgerAddr_c = new AddressProposition(addr_c)
  val forgerAddr_d = new AddressProposition(addr_d)

  @Test
  def testNullBlockFeeInfoSeq(): Unit = {
    val blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()
    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq)
    assertTrue(accountPaymentsList.isEmpty)
  }

  @Test
  def testHomogeneousBlockFeeInfoSeq(): Unit = {

    var blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()

    val abfi_a = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_a)
    val abfi_b = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_b)
    val abfi_c = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_c)

    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_a
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_b
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c

    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq)
    assertEquals(accountPaymentsList.length, 3)
    assertEquals(accountPaymentsList(0).value, BigInteger.valueOf(110))
    assertEquals(accountPaymentsList(1).value, BigInteger.valueOf(110))
    assertEquals(accountPaymentsList(2).value, BigInteger.valueOf(110))
  }

  @Test
  def testNotUniqueForgerAddresses(): Unit = {

    var blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()

    val abfi_a = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_a)
    val abfi_b = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_b)
    val abfi_c1 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_c)
    val abfi_c2 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_c)


    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_a
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_b
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c1
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c2

    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq)
    assertEquals(accountPaymentsList.length, 3)

    accountPaymentsList.foreach(
      payment => {
        if (payment.address.equals(forgerAddr_c))
          assertEquals(payment.value, BigInteger.valueOf(220))
        else
          assertEquals(payment.value, BigInteger.valueOf(110))
      }
    )
  }


  @Test
  def testPoolWithRemainder(): Unit = {

    var blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()

    val abfi_a = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(3),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_a)
    val abfi_b = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(3),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_b)
    val abfi_c1 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(4),
      forgerTips = BigInteger.valueOf(4),
      forgerAddr_c)
    val abfi_c2 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(4),
      forgerTips = BigInteger.valueOf(6),
      forgerAddr_c)


    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_a
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_b
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c1
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c2

    // poolFee is the sum of all baseFee contributions
    val poolFeeAmount = abfi_a.baseFee.add(abfi_b.baseFee.add(abfi_c1.baseFee.add(abfi_c2.baseFee)))
    // poolFee amount is shared by all contributors, even if a forger address is repeated: 14/4 = 3 with remainder 2
    val divAndRem: Array[BigInteger] = poolFeeAmount.divideAndRemainder(BigInteger.valueOf(blockFeeInfoSeq.size))
    assertEquals(divAndRem(0), BigInteger.valueOf(3))
    assertEquals(divAndRem(1), BigInteger.valueOf(2))

    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq)
    assertEquals(accountPaymentsList.length, 3)

    accountPaymentsList.foreach(
      payment => {
        if (payment.address.equals(forgerAddr_c))
          // last address is repeated, its reward are summed
          //   (forgerTip (4) + poolFee quota (3)) + (forgerTip (6) + poolFee quota (3))
          assertEquals(payment.value, BigInteger.valueOf((4 + 3) + (6 + 3)))
        else {
          // first 2 addresses have 1 satoshi more due to the remainder:
          //   forgerTip (10) + poolFee quota (3) + remainder quota (1)
          assertEquals(payment.value, BigInteger.valueOf(10 + 3 + 1))
        }
      }
    )
  }

  @Test
  def testWithMcForgerPoolRewards(): Unit = {
    var blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()

    val abfi_a = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_a)
    val abfi_b = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_b)
    val abfi_c1 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_c)
    val abfi_c2 = AccountBlockFeeInfo(
      baseFee = BigInteger.valueOf(100),
      forgerTips = BigInteger.valueOf(10),
      forgerAddr_c)

    val mcForgerPoolRewards = Map(
      forgerAddr_a -> BigInteger.valueOf(10),
      forgerAddr_b -> BigInteger.valueOf(10),
      forgerAddr_c -> BigInteger.valueOf(10),
      forgerAddr_d -> BigInteger.valueOf(10),

    )


    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_a
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_b
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c1
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c2

    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq, mcForgerPoolRewards)
    assertEquals(accountPaymentsList.length, 4)

    accountPaymentsList.foreach(
      payment => {
        if (payment.address.equals(forgerAddr_c))
          assertEquals(BigInteger.valueOf(230), payment.value)
        else if (payment.address.equals(forgerAddr_d))
          assertEquals(BigInteger.valueOf(10), payment.value)
        else
          assertEquals(BigInteger.valueOf(120), payment.value)
      }
    )
  }

  @Test
  def getMainchainWithdrawalEpochDistributionCapTest(): Unit = {
    val params = MainNetParams()
    val baseReward = 1250000000L
    val rewardAfterFirstHalving = baseReward / 2
    val rewardAfterSecondHalving = rewardAfterFirstHalving / 2
    val divider = 10

    // test 1 - before first halving
    var actual: BigInteger = getMainchainWithdrawalEpochDistributionCap(500, params)
    var expected: BigInteger = ZenWeiConverter.convertZenniesToWei(baseReward * params.withdrawalEpochLength / divider)
    assertEquals(expected, actual)
    // test 2 - at first halving
    actual = getMainchainWithdrawalEpochDistributionCap(840010, params)
    expected = ZenWeiConverter.convertZenniesToWei((baseReward * (params.withdrawalEpochLength - 10) / divider) + (rewardAfterFirstHalving * 10 / divider))
    assertEquals(expected, actual)
    // test 3 - after first halving
    actual = getMainchainWithdrawalEpochDistributionCap(1000010, params)
    expected = ZenWeiConverter.convertZenniesToWei(rewardAfterFirstHalving * params.withdrawalEpochLength / divider)
    assertEquals(expected, actual)
    // test 4 - at second halving
    actual = getMainchainWithdrawalEpochDistributionCap(1680010, params)
    expected = ZenWeiConverter.convertZenniesToWei((rewardAfterFirstHalving * (params.withdrawalEpochLength - 10) / divider) + (rewardAfterSecondHalving * 10 / divider))
    assertEquals(expected, actual)
  }

  @Test
  def getForgerAndDelegatorSharesTest(): Unit = {
    val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString("1122334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
    val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString("d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
    val forgerPublicKeys = ForgerPublicKeys(blockSignerProposition, vrfPublicKey)
    val rewardAddress: AddressProposition = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest1".getBytes(StandardCharsets.UTF_8)).publicImage()

    val mcForgerPoolRewards = Map(
      forgerAddr_a -> BigInteger.valueOf(10),
      forgerAddr_b -> BigInteger.valueOf(10),
      forgerAddr_c -> BigInteger.valueOf(10),
      forgerAddr_d -> BigInteger.valueOf(10),
    )

    val feePayment = AccountPayment(forgerAddr_a, BigInteger.valueOf(100))
    val forgerInfo = ForgerInfo(forgerPublicKeys, 100, rewardAddress)

    val (forgerPayment, delegatorPayment) = getForgerAndDelegatorShares(mcForgerPoolRewards, feePayment, forgerInfo)

    assertEquals(forgerPayment.address, forgerAddr_a)
    assertEquals(forgerPayment.value, BigInteger.valueOf(90))
    assertEquals(forgerPayment.valueFromMainchain.get, BigInteger.valueOf(9))
    assertEquals(forgerPayment.valueFromFees.get, BigInteger.valueOf(81))

    assertEquals(delegatorPayment.feePayment.address, rewardAddress)
    assertEquals(delegatorPayment.feePayment.value, BigInteger.valueOf(10))
    assertEquals(delegatorPayment.feePayment.valueFromMainchain.get, BigInteger.valueOf(1))
    assertEquals(delegatorPayment.feePayment.valueFromFees.get, BigInteger.valueOf(9))
    assertEquals(delegatorPayment.forgerKeys, forgerPublicKeys)
  }
}
