package io.horizen.account.utils

import io.horizen.account.network.ForgerInfo
import io.horizen.account.proposition.AddressProposition
import io.horizen.account.secret.PrivateKeySecp256k1Creator
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.account.utils.AccountFeePaymentsUtils.{getForgerAndDelegatorShares, getForgersRewards, getMainchainWithdrawalEpochDistributionCap}
import io.horizen.evm.Address
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
import scala.io.Source

class AccountFeePaymentsUtilsTest extends JUnitSuite with SidechainRelatedMainchainOutputFixture with MockitoSugar {
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
    val blockFeeInfoSeq: Seq[AccountBlockFeeInfo] = Seq()
    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq)
    assertTrue(accountPaymentsList.isEmpty)
  }

  @Test
  def testHomogeneousBlockFeeInfoSeq(): Unit = {

    var blockFeeInfoSeq: Seq[AccountBlockFeeInfo] = Seq()

    val abfi_a =
      AccountBlockFeeInfo(baseFee = BigInteger.valueOf(100), forgerTips = BigInteger.valueOf(10), forgerAddr_a)
    val abfi_b =
      AccountBlockFeeInfo(baseFee = BigInteger.valueOf(100), forgerTips = BigInteger.valueOf(10), forgerAddr_b)
    val abfi_c =
      AccountBlockFeeInfo(baseFee = BigInteger.valueOf(100), forgerTips = BigInteger.valueOf(10), forgerAddr_c)

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

    var blockFeeInfoSeq: Seq[AccountBlockFeeInfo] = Seq()

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

    accountPaymentsList.foreach(payment => {
      if (payment.identifier.getAddress.equals(forgerAddr_c))
        assertEquals(payment.value, BigInteger.valueOf(220))
      else
        assertEquals(payment.value, BigInteger.valueOf(110))
    })
  }

  @Test
  def testPoolWithRemainder(): Unit = {

    var blockFeeInfoSeq: Seq[AccountBlockFeeInfo] = Seq()

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

    accountPaymentsList.foreach(payment => {
      if (payment.identifier.getAddress.equals(forgerAddr_c))
        // last address is repeated, its reward are summed
        //   (forgerTip (4) + poolFee quota (3)) + (forgerTip (6) + poolFee quota (3))
        assertEquals(payment.value, BigInteger.valueOf((4 + 3) + (6 + 3)))
      else {
        // first 2 addresses have 1 satoshi more due to the remainder:
        //   forgerTip (10) + poolFee quota (3) + remainder quota (1)
        assertEquals(payment.value, BigInteger.valueOf(10 + 3 + 1))
      }
    })
  }

  @Test
  def testWithMcForgerPoolRewards(): Unit = {
    var blockFeeInfoSeq: Seq[AccountBlockFeeInfo] = Seq()

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
      new ForgerIdentifier(forgerAddr_a) -> BigInteger.valueOf(10),
      new ForgerIdentifier(forgerAddr_b) -> BigInteger.valueOf(10),
      new ForgerIdentifier(forgerAddr_c) -> BigInteger.valueOf(10),
      new ForgerIdentifier(forgerAddr_d) -> BigInteger.valueOf(10),
    )

    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_a
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_b
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c1
    blockFeeInfoSeq = blockFeeInfoSeq :+ abfi_c2

    val accountPaymentsList = getForgersRewards(blockFeeInfoSeq, mcForgerPoolRewards)
    assertEquals(accountPaymentsList.length, 4)

    accountPaymentsList.foreach(payment => {
      if (payment.identifier.getAddress.equals(forgerAddr_c))
        assertEquals(BigInteger.valueOf(230), payment.value)
      else if (payment.identifier.getAddress.equals(forgerAddr_d))
        assertEquals(BigInteger.valueOf(10), payment.value)
      else
        assertEquals(BigInteger.valueOf(120), payment.value)
    })
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

    val feePayment = ForgerPayment(new ForgerIdentifier(forgerAddr_a), BigInteger.valueOf(100), BigInteger.valueOf(10))
    val forgerInfo = ForgerInfo(forgerPublicKeys, 100, rewardAddress)

    val (forgerPayment, Some(delegatorPayment)) = getForgerAndDelegatorShares(feePayment, forgerInfo)

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

  @Test
  def testForgerRewardsOrdering_CornerCaseFromMainnet(): Unit = {
    val feeInfo = getMainnetExampleBlockFeeInfo
    val mcRewards = getMainnetExampleMcRewards

    val rewards = AccountFeePaymentsUtils.getForgersRewards(feeInfo, mcRewards)
      .map(fp => AccountPayment(fp.identifier.getAddress, fp.value))

    assertEquals(
      "47f5f036f2b6ec8224508af3c1a33f36662ccf305c46104fb60c071ee3774dbd",
      BytesUtils.toHexString(AccountFeePaymentsUtils.calculateFeePaymentsHash(rewards))
    )
  }

  private def getMainnetExampleMcRewards: Map[ForgerIdentifier, BigInteger] = {
    Map(
      new ForgerIdentifier(new AddressProposition(new Address("0x90826921d1d4aee8e6b5ae296f80b4145eb434df"))) -> new BigInteger("1294588159144"),
      new ForgerIdentifier(new AddressProposition(new Address("0x4bae5d28b45b88e1901eb691b5f71f6eadcd8b9f"))) -> new BigInteger("2589176318288"),
      new ForgerIdentifier(new AddressProposition(new Address("0x9c98454c8f4d2d38ad824b407be5448cf0fe7b0a"))) -> new BigInteger("3328940980656"),
      new ForgerIdentifier(new AddressProposition(new Address("0x6f47d5bb9c4e1f2ed25d442c1a45e43e197e8fbe"))) -> new BigInteger("462352913980"),
      new ForgerIdentifier(new AddressProposition(new Address("0x99d270f4a42b296fb888f168a5985e1d9839b064"))) -> new BigInteger("638925491828962"),
      new ForgerIdentifier(new AddressProposition(new Address("0xfac3dc3dc9b2562d8de5d30c00ad265210cd3d7a"))) -> new BigInteger("15350116744136"),
      new ForgerIdentifier(new AddressProposition(new Address("0xc9c8dd62a78c2cb9423d872d118b986c33ff7e3c"))) -> new BigInteger("629817139423556"),
      new ForgerIdentifier(new AddressProposition(new Address("0x54ac4a5c11b7e6ddeabbb99f69bdb59820a3607a"))) -> new BigInteger("645814550247264"),
      new ForgerIdentifier(new AddressProposition(new Address("0x1448283357e8fb6ea763a78836ffd5517149bf70"))) -> new BigInteger("6657881961312"),
      new ForgerIdentifier(new AddressProposition(new Address("0x0eef14a2db10cba19c3e13a4090f0dd3c669e459"))) -> new BigInteger("638185727166594"),
      new ForgerIdentifier(new AddressProposition(new Address("0x3f60469c1950a9b8b4f190a3168b59e354a2be6f"))) -> new BigInteger("3051529232268"),
      new ForgerIdentifier(new AddressProposition(new Address("0x7aaac8a2be835d9b9261018c68dba7166e775096"))) -> new BigInteger("2820352775278"),
      new ForgerIdentifier(new AddressProposition(new Address("0x0b3ee4a24ecf65bb4005219f873d915cbaac1b28"))) -> new BigInteger("593661141550320"),
      new ForgerIdentifier(new AddressProposition(new Address("0x6b5b8861f260457bb91ba604e8856d6ad7eb17a0"))) -> new BigInteger("924705827960"),
      new ForgerIdentifier(new AddressProposition(new Address("0x12ed8d94159083a64f97d382538b0881bd72429e"))) -> new BigInteger("92470582796"),
      new ForgerIdentifier(new AddressProposition(new Address("0xb545a82e49f9c595601c713765a05aea7590b2ed"))) -> new BigInteger("277411748388"),
      new ForgerIdentifier(new AddressProposition(new Address("0x8b4c5f6dfe440497fca3c13b8ab449b7d021682b"))) -> new BigInteger("648311255982756"),
      new ForgerIdentifier(new AddressProposition(new Address("0x6aa2ee3a3fa290ef0dc4900f7e19f26bcadfed74"))) -> new BigInteger("584414083270720"),
      new ForgerIdentifier(new AddressProposition(new Address("0xba2290aeaae3e1ea336431911c97a67ebff46528"))) -> new BigInteger("33011998058172"),
      new ForgerIdentifier(new AddressProposition(new Address("0x28a48c183df1e30f64673cb4c84d7fd7df4ad506"))) -> new BigInteger("3077698407182838"),
      new ForgerIdentifier(new AddressProposition(new Address("0x85f79ba831a8b1716eff9726f2be54e079e75c62"))) -> new BigInteger("1941882238716"),
      new ForgerIdentifier(new AddressProposition(new Address("0x62b1bc6fd237b775138d910274ff2911d7aea5cc"))) -> new BigInteger("624453845621388"),
      new ForgerIdentifier(new AddressProposition(new Address("0x19f78fca9a4ee0dd795bf9a8277aee241bb972db"))) -> new BigInteger("602584552790134"),
      new ForgerIdentifier(new AddressProposition(new Address("0x8eb44f8b1c03d6d194f3ace68e1e0a4a696d44d9"))) -> new BigInteger("646276903161244"),
      new ForgerIdentifier(new AddressProposition(new Address("0xac5722e85196c0ca9b7c0c00ec8f7ccf7b4d913c"))) -> new BigInteger("596157847285812"),
      new ForgerIdentifier(new AddressProposition(new Address("0x0afbde33475321e870c55be95a3e6283b0385f80"))) -> new BigInteger("1895646947318"),
    )
  }

  private def getMainnetExampleBlockFeeInfo: Seq[AccountBlockFeeInfo] = {
    var blockFeeInfoSeq : Seq[AccountBlockFeeInfo] = Seq()
    val source = Source.fromURL(getClass.getResource("/block_fee_info_seq.dsv"))
    source.getLines().foreach(
      line => {
        val parts = line.split(" ")
        val baseFee = new BigInteger(parts(0))
        val forgerTips = new BigInteger(parts(1))
        val forgerAddress = new AddressProposition(new Address(parts(2)))
        blockFeeInfoSeq = blockFeeInfoSeq :+ AccountBlockFeeInfo(baseFee, forgerTips, forgerAddress)
      }
    )
    source.close()
    blockFeeInfoSeq
  }

}
