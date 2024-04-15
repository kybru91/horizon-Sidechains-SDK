package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.network.ForgerInfo
import io.horizen.account.proposition.AddressProposition
import io.horizen.account.state._
import io.horizen.account.state.nativescdata.forgerstakev2.StakeStorage._
import io.horizen.account.utils.WellKnownAddresses.FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
import io.horizen.account.utils.ZenWeiConverter
import io.horizen.evm.Address
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.utils.BytesUtils
import org.junit.Assert._
import org.junit.Test
import org.scalatestplus.junit.JUnitSuite

import java.math.BigInteger
import scala.collection.mutable.ListBuffer
import scala.language.implicitConversions

class StakeStorageTest
  extends JUnitSuite
    with MessageProcessorFixture {

  val blockSignerProposition1 = new PublicKey25519Proposition(BytesUtils.fromHexString("1122334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
  val vrfPublicKey1 = new VrfPublicKey(BytesUtils.fromHexString("d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
  val forger1Key: ForgerKey = ForgerKey(blockSignerProposition1, vrfPublicKey1)

  val blockSignerProposition2 = new PublicKey25519Proposition(BytesUtils.fromHexString("4455334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
  val vrfPublicKey2 = new VrfPublicKey(BytesUtils.fromHexString("445575fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
  val forger2Key: ForgerKey = ForgerKey(blockSignerProposition2, vrfPublicKey2)

  val blockSignerProposition3 = new PublicKey25519Proposition(BytesUtils.fromHexString("5555334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
  val vrfPublicKey3 = new VrfPublicKey(BytesUtils.fromHexString("555575fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
  val forger3Key: ForgerKey = ForgerKey(blockSignerProposition3, vrfPublicKey3)

  val delegator1 = new Address("0xaaa00001230000000000deadbeefaaaa2222de01")
  val delegator2 = new Address("0xaaa00001230000000000aaaaaaabbbbb2222de02")
  val delegator3 = new Address("0xaaabbbb1230000000000aaaaaaabbbbb2222de03")

  implicit def addressToChecksumAddress(t: Address): DelegatorKey = DelegatorKey(t)

  @Test
  def testAddForger(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      var result = StakeStorage.getPagedListOfForgers(view, 0, 10)

      assertTrue(result.forgers.isEmpty)
      assertEquals(-1, result.nextStartPos)
      val epochNumber = 135869

      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93
      val stakeAmount = BigInteger.TEN

      assertTrue(StakeStorage.getForger(view, blockSignerProposition1, vrfPublicKey1).isEmpty)

      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount)

      result = StakeStorage.getPagedListOfForgers(view, 0, 10)

      var listOfForgers = result.forgers
      assertEquals(1, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers.head.rewardAddress.address())
      assertEquals(rewardShare, listOfForgers.head.rewardShare)
      assertEquals(-1, result.nextStartPos)

      assertEquals(listOfForgers.head, StakeStorage.getForger(view, blockSignerProposition1, vrfPublicKey1).get)

      val delegatorList = DelegatorList(forger1Key)
      assertEquals(1, delegatorList.getSize(view))
      assertEquals(delegator1, delegatorList.getDelegatorAt(view, 0))


      val forger1History = ForgerStakeHistory(forger1Key)
      assertEquals(1, forger1History.getSize(view))
      assertEquals(epochNumber, forger1History.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount, forger1History.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount, forger1History.getLatestAmount(view))

      val stakeHistory = StakeHistory(forger1Key, delegator1)
      assertEquals(1, stakeHistory.getSize(view))
      assertEquals(epochNumber, stakeHistory.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount, stakeHistory.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount, stakeHistory.getLatestAmount(view))

      val forgerList = DelegatorListOfForgerKeys(delegator1)
      assertEquals(1, forgerList.getSize(view))
      assertEquals(forger1Key, forgerList.getForgerKey(view, 0))


      //  Try to register twice the same forger. It should fail
      val ex = intercept[ExecutionRevertedException] {
        StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount)
      }
      assertEquals("Forger already registered.", ex.getMessage)

      // Try to register another forger with the same delegator and the same rewardAddress
      val rewardShare2 = 87
      val stakeAmount2 = ZenWeiConverter.MAX_MONEY_IN_WEI
      val epochNumber2 = 444555444
      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare2, rewardAddress, epochNumber2, delegator1, stakeAmount2)

      result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      listOfForgers = result.forgers
      assertEquals(2, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)

      assertEquals(blockSignerProposition2, listOfForgers(1).forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey2, listOfForgers(1).forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers(1).rewardAddress.address())
      assertEquals(rewardShare2, listOfForgers(1).rewardShare)
      assertEquals(-1, result.nextStartPos)

      // Check that the first forger was not changed
      assertEquals(1, delegatorList.getSize(view))
      assertEquals(delegator1, delegatorList.getDelegatorAt(view, 0))

      assertEquals(1, forger1History.getSize(view))
      assertEquals(epochNumber, forger1History.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount, forger1History.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount, forger1History.getLatestAmount(view))

      assertEquals(1, stakeHistory.getSize(view))
      assertEquals(epochNumber, stakeHistory.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount, stakeHistory.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount, stakeHistory.getLatestAmount(view))

      // Check second forger
      val delegatorList2 = DelegatorList(forger2Key)
      assertEquals(1, delegatorList2.getSize(view))
      assertEquals(delegator1, delegatorList2.getDelegatorAt(view, 0))

      val forgerHistory2 = ForgerStakeHistory(forger2Key)
      assertEquals(1, forgerHistory2.getSize(view))
      assertEquals(epochNumber2, forgerHistory2.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount2, forgerHistory2.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount2, forgerHistory2.getLatestAmount(view))

      val stakeHistory2 = StakeHistory(forger2Key, delegator1)
      assertEquals(1, stakeHistory2.getSize(view))
      assertEquals(epochNumber2, stakeHistory2.getCheckpoint(view, 0).fromEpochNumber)
      assertEquals(stakeAmount2, stakeHistory2.getCheckpoint(view, 0).stakedAmount)
      assertEquals(stakeAmount2, stakeHistory2.getLatestAmount(view))

      assertEquals(2, forgerList.getSize(view))
      assertEquals(forger1Key, forgerList.getForgerKey(view, 0))
      assertEquals(forger2Key, forgerList.getForgerKey(view, 1))

      // Add a forger without reward address
      val blockSignerProposition3 = new PublicKey25519Proposition(BytesUtils.fromHexString("3333334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
      val vrfPublicKey3 = new VrfPublicKey(BytesUtils.fromHexString("333375fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
      StakeStorage.addForger(view, blockSignerProposition3, vrfPublicKey3, 0, Address.ZERO, epochNumber2, delegator1, stakeAmount2)

      result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      listOfForgers = result.forgers
      assertEquals(3, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)

      assertEquals(blockSignerProposition2, listOfForgers(1).forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey2, listOfForgers(1).forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers(1).rewardAddress.address())
      assertEquals(rewardShare2, listOfForgers(1).rewardShare)

      assertEquals(blockSignerProposition3, listOfForgers(2).forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey3, listOfForgers(2).forgerPublicKeys.vrfPublicKey)
      assertEquals(Address.ZERO, listOfForgers(2).rewardAddress.address())
      assertEquals(0, listOfForgers(2).rewardShare)

      assertEquals(-1, result.nextStartPos)
    }
  }


  @Test
  def testGetPagedListOfForgers(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      val result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      assertTrue(result.forgers.isEmpty)
      assertEquals(-1, result.nextStartPos)

      assertThrows[ExecutionRevertedException] {
        StakeStorage.getPagedListOfForgers(view, 0, 0)
      }

      assertThrows[ExecutionRevertedException] {
        StakeStorage.getPagedListOfForgers(view, 1, 10)
      }

      assertThrows[ExecutionRevertedException] {
        StakeStorage.getPagedListOfForgers(view, 1, -10)
      }

      assertThrows[ExecutionRevertedException] {
        StakeStorage.getPagedListOfForgers(view, -1, 10)
      }

      val numOfForgers = 100
      val listOfExpectedData = (0 until numOfForgers).map { idx =>
        val postfix = f"$idx%03d"
        val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString(s"1122334455667788112233445566778811223344556677881122334455667$postfix")) // 32 bytes
        val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString(s"d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1$postfix")) // 33 bytes

        val delegator = new Address(s"0xaaa00001230000000000deadbeefaaaa22222$postfix")
        val epochNumber = 135869 + idx

        val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222$postfix")
        val rewardShare = idx + 1
        val stakeAmount = ZenWeiConverter.convertZenniesToWei(idx + 1)

        StakeStorage.addForger(view, blockSignerProposition, vrfPublicKey, rewardShare, rewardAddress, epochNumber, delegator, stakeAmount)


        val forgerKey = ForgerKey(blockSignerProposition, vrfPublicKey)
        val delegatorList = DelegatorList(forgerKey)
        assertEquals(1, delegatorList.getSize(view))
        assertEquals(delegator, delegatorList.getDelegatorAt(view, 0))

        val forgerHistory = ForgerStakeHistory(forgerKey)
        assertEquals(1, forgerHistory.getSize(view))
        assertEquals(epochNumber, forgerHistory.getCheckpoint(view, 0).fromEpochNumber)
        assertEquals(stakeAmount, forgerHistory.getCheckpoint(view, 0).stakedAmount)
        assertEquals(stakeAmount, forgerHistory.getLatestAmount(view))

        val stakeHistory = StakeHistory(forgerKey, delegator)
        assertEquals(1, stakeHistory.getSize(view))
        assertEquals(epochNumber, stakeHistory.getCheckpoint(view, 0).fromEpochNumber)
        assertEquals(stakeAmount, stakeHistory.getCheckpoint(view, 0).stakedAmount)
        assertEquals(stakeAmount, stakeHistory.getLatestAmount(view))

        val forgerList = DelegatorListOfForgerKeys(delegator)
        assertEquals(1, forgerList.getSize(view))
        assertEquals(forgerKey, forgerList.getForgerKey(view, 0))

        (blockSignerProposition, vrfPublicKey, rewardAddress, rewardShare)
      }

      val pageSize = 11
      var continue = true
      var listOfResults = Seq.empty[ForgerInfo]
      var startPos = 0

      while (continue) {
        val result = StakeStorage.getPagedListOfForgers(view, startPos, pageSize)
        listOfResults = listOfResults ++ result.forgers
        continue = if (result.nextStartPos != -1) {
          assertEquals(pageSize, result.forgers.size)
          true
        }
        else
          false
        startPos = result.nextStartPos
      }

      assertEquals(listOfExpectedData.size, listOfResults.size)
      (0 until numOfForgers).foreach { idx =>
        val (blockSignerProposition, vrfPublicKey, rewardAddress, rewardShare) = listOfExpectedData(idx)
        val forgerInfo = listOfResults(idx)
        assertEquals(blockSignerProposition, forgerInfo.forgerPublicKeys.blockSignPublicKey)
        assertEquals(vrfPublicKey, forgerInfo.forgerPublicKeys.vrfPublicKey)
        assertEquals(rewardAddress, forgerInfo.rewardAddress.address())
        assertEquals(rewardShare, forgerInfo.rewardShare)
      }

    }
  }

  @Test
  def testAddStake(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      // Check that we don't have any forger yet
      var result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      assertTrue(result.forgers.isEmpty)

      val epochNumber1 = 135869
      val stakeAmount1 = BigInteger.valueOf(300)

      // Add stake to a non-registered forger. it should fail
      var ex = intercept[ExecutionRevertedException] {
        StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)
      }
      assertEquals("Forger doesn't exist.", ex.getMessage)

      // Register the forger and try again adding stakes
      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93
      val initialEpochNumber = 125869
      val initialStakeAmount = BigInteger.TEN
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, initialEpochNumber, delegator1, initialStakeAmount)

      result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      var listOfForgers = result.forgers
      assertEquals(1, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers.head.rewardAddress.address())
      assertEquals(rewardShare, listOfForgers.head.rewardShare)
      assertEquals(-1, result.nextStartPos)

      var listOfExpectedForger1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil
      var listOfExpectedD1F1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil

      // Add stake using the same delegator
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)

      val forger1DelegatorList = DelegatorList(forger1Key)
      assertEquals(1, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))

      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber1, listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount1))
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber1, listOfExpectedD1F1Checkpoints.last.stakedAmount.add(stakeAmount1))

      val forger1History = ForgerStakeHistory(forger1Key)
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      val stakeHistory_d1_f1 = StakeHistory(forger1Key, delegator1)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      val delegator1ForgerList = DelegatorListOfForgerKeys(delegator1)
      assertEquals(1, delegator1ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Add another stake from the same delegator in the same consensus epoch

      val stakeAmount2 = BigInteger.valueOf(1000)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount2)

      // delegator list shouldn't change
      assertEquals(1, forger1DelegatorList.getSize(view))

      // ForgerHistory size should remain the same, but the value of the last checkpoint should change
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints.updated(1, StakeCheckpoint(epochNumber1,
        listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount2)))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      // StakeHistory size should remain the same, but the value of the last checkpoint should change
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints.updated(1, StakeCheckpoint(epochNumber1,
        listOfExpectedD1F1Checkpoints.last.stakedAmount.add(stakeAmount2)))
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // forger list of first delegator shouldn't change
      assertEquals(1, delegator1ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Add another stake from the another delegator in the same consensus epoch
      val stakeAmount_2_1 = BigInteger.valueOf(753536)

      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator2, stakeAmount_2_1)

      //Check delegator list
      assertEquals(2, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))
      assertEquals(delegator2, forger1DelegatorList.getDelegatorAt(view, 1))

      // ForgerHistory size should remain the same, but the value of the last checkpoint should change
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints.updated(1, StakeCheckpoint(epochNumber1, listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount_2_1)))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      val stakeHistory_d2_f1 = StakeHistory(forger1Key, delegator2)
      var listOfExpectedD2F1Checkpoints = StakeCheckpoint(epochNumber1, stakeAmount_2_1) :: Nil
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

      // Check delegator2 forger list
      val delegator2ForgerList = DelegatorListOfForgerKeys(delegator2)
      assertEquals(1, delegator2ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Add another stake from the second delegator in a different consensus epoch
      val stakeAmount_2_2 = BigInteger.valueOf(22356)
      val epochNumber2 = epochNumber1 + 10
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber2, delegator2, stakeAmount_2_2)

      //Check delegator list, shouldn't change
      assertEquals(2, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))
      assertEquals(delegator2, forger1DelegatorList.getDelegatorAt(view, 1))

      // Check ForgerHistory, we should have 3 checkpoints
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber2, listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount_2_2))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      // Check delegator1 stake history, shouldn't change
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Check delegator2 stake history, we should have 2 checkpoints
      listOfExpectedD2F1Checkpoints = listOfExpectedD2F1Checkpoints :+ StakeCheckpoint(epochNumber2, listOfExpectedD2F1Checkpoints.last.stakedAmount.add(stakeAmount_2_2))
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

      // Check delegator1 forger list
      assertEquals(1, delegator1ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Check delegator2 forger list
      assertEquals(1, delegator2ForgerList.getSize(view))
      assertEquals(forger1Key, delegator2ForgerList.getForgerKey(view, 0))

      // Register another forger with delegator2
      val epochNumber3 = epochNumber2 + 65

      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare, rewardAddress, epochNumber3, delegator2, initialStakeAmount)

      result = StakeStorage.getPagedListOfForgers(view, 0, 10)

      listOfForgers = result.forgers
      assertEquals(2, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers.head.rewardAddress.address())
      assertEquals(rewardShare, listOfForgers.head.rewardShare)

      assertEquals(blockSignerProposition2, listOfForgers(1).forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey2, listOfForgers(1).forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers(1).rewardAddress.address())
      assertEquals(rewardShare, listOfForgers(1).rewardShare)
      assertEquals(-1, result.nextStartPos)

      // Check delegator2 forger list
      assertEquals(2, delegator2ForgerList.getSize(view))
      assertEquals(forger1Key, delegator2ForgerList.getForgerKey(view, 0))
      assertEquals(forger2Key, delegator2ForgerList.getForgerKey(view, 1))

      // Check delegator2/forger1 stake history, shouldn't change
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

      // Check delegator2/forger2 stake history
      val stakeHistory_d2_f2 = StakeHistory(forger2Key, delegator2)
      val listOfExpectedD2F2Checkpoints = StakeCheckpoint(epochNumber3, initialStakeAmount) :: Nil
      checkStakeHistory(view, stakeHistory_d2_f2, listOfExpectedD2F2Checkpoints)

      // Add stake using a delegator address all upper case. It should be treated as the same delegator.

      val epochNumber4 = epochNumber3 + 10
      val DELEGATOR1 = new Address("0x" + delegator1.toStringNoPrefix.toUpperCase)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber4, DELEGATOR1, stakeAmount1)

      assertEquals(2, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))
      assertEquals(delegator2, forger1DelegatorList.getDelegatorAt(view, 1))

      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber4, listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount1))
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber4, listOfExpectedD1F1Checkpoints.last.stakedAmount.add(stakeAmount1))

      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      assertArrayEquals(delegator1ForgerList.keySeed, DelegatorListOfForgerKeys(DELEGATOR1).keySeed)

      // Test with epoch before the last one. It should fail.
      val badEpoch = epochNumber2 - 10
      ex = intercept[ExecutionRevertedException] {
        StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, badEpoch, delegator2, stakeAmount_2_2)
      }
      assertEquals(s"Epoch is in the past: epoch $badEpoch, last epoch: $epochNumber4", ex.getMessage)

    }
  }

  @Test
  def testRemoveStake(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      // Check that we don't have any forger yet
      var result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      assertTrue(result.forgers.isEmpty)

      val epochNumber1 = 135869
      val stakeAmount1 = BigInteger.valueOf(5358869)

      // Remove stake from a non-registered forger, it should fail
      var ex = intercept[ExecutionRevertedException] {
        StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)
      }
      assertEquals("Forger doesn't exist.", ex.getMessage)

      // Register the forger and try again removing stakes
      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93
      val initialEpochNumber = 125869
      val initialStakeAmount = ZenWeiConverter.MAX_MONEY_IN_WEI

      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, initialEpochNumber, delegator1, initialStakeAmount)
      result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      val listOfForgers = result.forgers
      assertEquals(1, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers.head.rewardAddress.address())
      assertEquals(rewardShare, listOfForgers.head.rewardShare)
      assertEquals(-1, result.nextStartPos)

      var listOfExpectedForger1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil
      var listOfExpectedD1F1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil

      // Remove stake using the same delegator
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)

      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber1, listOfExpectedForger1Checkpoints.last.stakedAmount.subtract(stakeAmount1))
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber1, listOfExpectedD1F1Checkpoints.last.stakedAmount.subtract(stakeAmount1))

      val forger1DelegatorList = DelegatorList(forger1Key)
      assertEquals(1, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))

      val forger1History = ForgerStakeHistory(forger1Key)
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      val stakeHistory_d1_f1 = StakeHistory(forger1Key, delegator1)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      val delegator1ForgerList = DelegatorListOfForgerKeys(delegator1)
      assertEquals(1, delegator1ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Remove another stake from the same delegator in the same consensus epoch, using a delegator address all upper case
      // It should be treated as the same delegator.

      val DELEGATOR1 = new Address("0x" + delegator1.toStringNoPrefix.toUpperCase)
      val stakeAmount2 = BigInteger.valueOf(1000)
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, DELEGATOR1, stakeAmount2)

      // delegator list shouldn't change
      assertEquals(1, forger1DelegatorList.getSize(view))

      // ForgerHistory size should remain the same, but the value of the last checkpoint should change
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints.updated(1, StakeCheckpoint(epochNumber1, listOfExpectedForger1Checkpoints.last.stakedAmount.subtract(stakeAmount2)))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      // StakeHistory size should remain the same, but the value of the last checkpoint should change
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints.updated(1, StakeCheckpoint(epochNumber1, listOfExpectedD1F1Checkpoints.last.stakedAmount.subtract(stakeAmount2)))
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // forger list of first delegator shouldn't change
      assertEquals(1, delegator1ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Remove stake from the another delegator. It should fail
      val stakeAmount_2_1 = BigInteger.valueOf(753536)

      assertThrows[ExecutionRevertedException] {
        StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator2, stakeAmount_2_1)
      }

      //Add some stake for delegator 2
      val epochNumber2 = epochNumber1 + 10
      val stakeAmount_2_2 = stakeAmount_2_1.multiply(BigInteger.TEN)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber2, delegator2, stakeAmount_2_2)

      //Check delegator list
      assertEquals(2, forger1DelegatorList.getSize(view))
      assertEquals(delegator1, forger1DelegatorList.getDelegatorAt(view, 0))
      assertEquals(delegator2, forger1DelegatorList.getDelegatorAt(view, 1))

      // Check ForgerHistory
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber2, listOfExpectedForger1Checkpoints.last.stakedAmount.add(stakeAmount_2_2))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      val stakeHistory_d2_f1 = StakeHistory(forger1Key, delegator2)
      var listOfExpectedD2F1Checkpoints = StakeCheckpoint(epochNumber2, stakeAmount_2_2) :: Nil
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

      // Check delegator2 forger list
      val delegator2ForgerList = DelegatorListOfForgerKeys(delegator2)
      assertEquals(1, delegator2ForgerList.getSize(view))
      assertEquals(forger1Key, delegator1ForgerList.getForgerKey(view, 0))

      // Check delegator1/forger1 stake, it shouldn't change
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Remove stake from delegator2 from another epoch
      val epochNumber3 = epochNumber2 + 4756
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber3, delegator2, stakeAmount_2_1)

      // Check ForgerHistory
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber3, listOfExpectedForger1Checkpoints.last.stakedAmount.subtract(stakeAmount_2_1))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      listOfExpectedD2F1Checkpoints = listOfExpectedD2F1Checkpoints :+ StakeCheckpoint(epochNumber3, listOfExpectedD2F1Checkpoints.last.stakedAmount.subtract(stakeAmount_2_1))
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

      // Remove stake from delegator1 from same epoch
      val stakeAmount3 = BigInteger.valueOf(1000)
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber3, delegator1, stakeAmount3)

      // Check ForgerHistory
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints.updated(listOfExpectedForger1Checkpoints.size - 1,
        StakeCheckpoint(epochNumber3, listOfExpectedForger1Checkpoints.last.stakedAmount.subtract(stakeAmount3)))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber3, listOfExpectedD1F1Checkpoints.last.stakedAmount.subtract(stakeAmount3))
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Try to remove stake with epoch before the last one. It should fail.
      val badEpoch = epochNumber3 - 10
      ex = intercept[ExecutionRevertedException] {
        StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, badEpoch, delegator2, stakeAmount_2_1)
      }
      assertEquals(s"Epoch is in the past: epoch $badEpoch, last epoch: $epochNumber3", ex.getMessage)

      // Try to remove more stake than available. It should fail
      val epochNumber4 = epochNumber3 + 44
      assertThrows[ExecutionRevertedException] {
        StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber4, delegator1, listOfExpectedD1F1Checkpoints.last.stakedAmount.add(BigInteger.ONE))
      }

      // Try to remove all delegator1 stake. History should remain available
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber4, delegator1, listOfExpectedD1F1Checkpoints.last.stakedAmount)
      // Check ForgerHistory
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber4, listOfExpectedForger1Checkpoints.last.stakedAmount.subtract(listOfExpectedD1F1Checkpoints.last.stakedAmount))
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber4, BigInteger.ZERO)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Try to remove all delegator2 stake. History should remain available
      val epochNumber5 = epochNumber4 + 12
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber5, delegator2, listOfExpectedD2F1Checkpoints.last.stakedAmount)
      // Check ForgerHistory
      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber5, BigInteger.ZERO)
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      listOfExpectedD2F1Checkpoints = listOfExpectedD2F1Checkpoints :+ StakeCheckpoint(epochNumber5, BigInteger.ZERO)
      checkStakeHistory(view, stakeHistory_d2_f1, listOfExpectedD2F1Checkpoints)

    }
  }

  @Test
  def testDuplicateCheckpoints(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      // Register the forger and try again removing stakes
      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93
      val initialEpochNumber = 125869
      val initialStakeAmount = BigInteger.valueOf(5358869)

      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, initialEpochNumber, delegator1, initialStakeAmount)

      // Remove and then add again the same amount in the same epoch of the registration. Check everything works

      val stakeAmount1 = BigInteger.valueOf(5358869)

      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, initialEpochNumber, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, initialEpochNumber, delegator1, stakeAmount1)

      var listOfExpectedForger1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil
      var listOfExpectedD1F1Checkpoints = StakeCheckpoint(initialEpochNumber, initialStakeAmount) :: Nil

      val forger1History = ForgerStakeHistory(forger1Key)
      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)

      val stakeHistory_d1_f1 = StakeHistory(forger1Key, delegator1)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Let's do the same but in another epoch. The stake history should not becomes bigger

      val epochNumber1 = 135869
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount1)

      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

      // Add again another stake in the same epoch. Check that we have a new checkpoint
      val stakeAmount2 = BigInteger.valueOf(5555555)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber1, delegator1, stakeAmount2)

      listOfExpectedForger1Checkpoints = listOfExpectedForger1Checkpoints :+ StakeCheckpoint(epochNumber1, initialStakeAmount.add(stakeAmount2))
      listOfExpectedD1F1Checkpoints = listOfExpectedD1F1Checkpoints :+ StakeCheckpoint(epochNumber1, initialStakeAmount.add(stakeAmount2))

      checkStakeHistory(view, forger1History, listOfExpectedForger1Checkpoints)
      checkStakeHistory(view, stakeHistory_d1_f1, listOfExpectedD1F1Checkpoints)

    }
  }


  @Test
  def testGetAllForgerStakes(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      var listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertTrue(listOfStakes.isEmpty)

      val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222111")
      val rewardShare = 90
      var epochNumber = 135869
      val stakeAmount1 = BigInteger.valueOf(10000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount1)
      var listOfExpectedData = ForgerStakeData(ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1), new AddressProposition(delegator1), stakeAmount1) :: Nil

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)

      epochNumber += 10

      val stakeAmount2 = BigInteger.valueOf(20000000000L)
      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount2)
      listOfExpectedData = listOfExpectedData :+ ForgerStakeData(ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), new AddressProposition(delegator1), stakeAmount2)

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)

      epochNumber += 10
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber, delegator1, stakeAmount1)
      listOfExpectedData = listOfExpectedData.updated(0, ForgerStakeData(ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1), new AddressProposition(delegator1), stakeAmount1.add(stakeAmount1)))

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)

      epochNumber += 10
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, epochNumber, delegator2, stakeAmount1)
      listOfExpectedData = listOfExpectedData :+ ForgerStakeData(ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), new AddressProposition(delegator2), stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, epochNumber, delegator3, stakeAmount2)
      listOfExpectedData = listOfExpectedData :+ ForgerStakeData(ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), new AddressProposition(delegator3), stakeAmount2)

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)

      //  Remove all forger2/delegator3 stakes. forger2/delegator3 stake shouldn't be in the resulting list
      epochNumber += 10
      StakeStorage.removeStake(view, blockSignerProposition2, vrfPublicKey2, epochNumber, delegator3, stakeAmount2)
      listOfExpectedData = listOfExpectedData.slice(0, listOfExpectedData.size - 1)
      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)


      //  Remove all forger1 stakes. forger1 shouldn't be in the resulting list
      epochNumber += 10
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber, delegator1, stakeAmount1.add(stakeAmount1))
      listOfExpectedData = listOfExpectedData.slice(1, listOfExpectedData.size)
      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(listOfExpectedData, listOfStakes)

    }
  }

  @Test
  def testGetPagedForgerStakes(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      // check that at the very beginning we have empty lists
      val listOfStakesForgerEmpty = StakeStorage.getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1), 0, 100)
      assertTrue(listOfStakesForgerEmpty.stakesData.isEmpty)
      assertTrue(listOfStakesForgerEmpty.nextStartPos == -1)

      val listOfStakesDelegatorEmpty = StakeStorage.getPagedForgersStakesByDelegator(view, delegator1, 0, 100)
      assertTrue(listOfStakesDelegatorEmpty.stakesData.isEmpty)
      assertTrue(listOfStakesDelegatorEmpty.nextStartPos == -1)

      val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222111")
      val rewardShare = 100
      val epochNumber = 1000

      val stakeAmount1 = BigInteger.valueOf(10000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount1)

      val stakeAmount2 = BigInteger.valueOf(20000000000L)
      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare, rewardAddress, epochNumber, delegator1, stakeAmount2)

      val stakeAmount3 = BigInteger.valueOf(40000000000L)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber, delegator1, stakeAmount3)

      val stakeAmount4 = BigInteger.valueOf(80000000000L)
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, epochNumber, delegator2, stakeAmount4)

      val stakeAmount5 = BigInteger.valueOf(160000000000L)
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, epochNumber, delegator3, stakeAmount5)

      val listOfStakesForger1 = StakeStorage.getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1), 0, 100)
      // check forger1 has 1! delegator with staked amount as the sum of two contributions
      assertTrue(listOfStakesForger1.stakesData.size == 1)
      assertEquals(listOfStakesForger1.stakesData.head.delegator.address(), delegator1)
      assertTrue(listOfStakesForger1.stakesData.head.stakedAmount.equals(stakeAmount1.add(stakeAmount3)))

      val listOfStakesForger2 = StakeStorage.getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 0, 100)
      // check forger2 has 3 delegators with expected stake amount
      assertTrue(listOfStakesForger2.stakesData.size == 3)
      var count = 0
      listOfStakesForger2.stakesData.foreach(entry => {
        if (entry.delegator.address().equals(delegator1)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount2))
          count += 1
        } else if (entry.delegator.address().equals(delegator2)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount4))
          count += 1
        } else if (entry.delegator.address().equals(delegator3)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount5))
          count += 1
        } else {
          fail("Unexpected entry")
        }
      })
      assertEquals(3, count)

      // get the result on two pages
      val listOfStakesForger2_page1 = StakeStorage.getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 0, 2)
      assertTrue(listOfStakesForger2_page1.stakesData.size == 2)
      assertTrue(listOfStakesForger2_page1.nextStartPos == 2)

      val listOfStakesForger2_page2 = StakeStorage.getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 2, 1)
      assertTrue(listOfStakesForger2_page2.stakesData.size == 1)
      assertTrue(listOfStakesForger2_page2.nextStartPos == -1)

      // check the two pages joint together are the same as before
      assertEquals(listOfStakesForger2_page1.stakesData ++ listOfStakesForger2_page2.stakesData, listOfStakesForger2.stakesData)

      // get stakes by delegator
      val listOfStakesByDelegator1 = getPagedForgersStakesByDelegator(view, delegator1, 0, 5)
      // check we have 2 records, one for each forger
      count = 0
      assertTrue(listOfStakesByDelegator1.stakesData.size == 2)
      listOfStakesByDelegator1.stakesData.foreach(entry => {
        if (entry.forgerPublicKeys.toString.equals(ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1).toString)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount1.add(stakeAmount3)))
          count += 1
        } else if (entry.forgerPublicKeys.toString.equals(ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2).toString)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount2))
          count += 1
        } else {
          fail("Unexpected entry")
        }
      })
      assertEquals(2, count)

      // get the result on two pages
      val listOfStakesDelegator1_page1 = getPagedForgersStakesByDelegator(view, delegator1, 0, 1)
      assertTrue(listOfStakesDelegator1_page1.stakesData.size == 1)
      assertTrue(listOfStakesDelegator1_page1.nextStartPos == 1)

      val listOfStakesDelegator1_page2 = getPagedForgersStakesByDelegator(view, delegator1, 1, 1)
      assertTrue(listOfStakesDelegator1_page2.stakesData.size == 1)
      assertTrue(listOfStakesDelegator1_page2.nextStartPos == -1)

      // check the two pages joint together are the same as before
      assertEquals(listOfStakesDelegator1_page1.stakesData ++ listOfStakesDelegator1_page2.stakesData, listOfStakesByDelegator1.stakesData)

      // remove all the stakes of delegator 1 for forger 1, check we do not have it anymore in the list
      StakeStorage.removeStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber, delegator1, stakeAmount1.add(stakeAmount3))
      // get stakes by delegator
      val listOfStakesByDelegator1_rem = getPagedForgersStakesByDelegator(view, delegator1, 0, 5)
      // check we have 1 record, only forger2
      assertTrue(listOfStakesByDelegator1_rem.stakesData.size == 1)
      count = 0
      listOfStakesByDelegator1_rem.stakesData.foreach(entry => {
        if (entry.forgerPublicKeys.toString.equals(ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2).toString)) {
          assertTrue(entry.stakedAmount.equals(stakeAmount2))
          count += 1
        } else {
          fail("Unexpected entry")
        }
      })
      assertEquals(1, count)

      // negative tests for 'by forger'
      // - invalid start pos
      var ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 4, 5)
      }
      assertTrue(ex.getMessage.contains("Invalid start position"))

      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), -1, 5)
      }
      assertTrue(ex.getMessage.contains("Negative start position"))

      // - invalid page size
      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 0, 0)
      }
      assertTrue(ex.getMessage.contains("Invalid page size"))

      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey2), 0, -1)
      }
      assertTrue(ex.getMessage.contains("Invalid page size"))

      // - null forger
      assertThrows[NullPointerException] {
        getPagedForgersStakesByForger(view, null, 0, 2)
      }
      // we throw an exception on an empty list if we specify bad start pos
      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByForger(view, ForgerPublicKeys(blockSignerProposition2, vrfPublicKey1), 1, 100)
      }
      assertTrue(ex.getMessage.contains("Invalid start position"))

      // negative tests for 'by delegator'
      // - invalid start pos
      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByDelegator(view, delegator1, 4, 5)
      }
      assertTrue(ex.getMessage.contains("Invalid start position"))

      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByDelegator(view, delegator1, -1, 5)
      }
      assertTrue(ex.getMessage.contains("Negative start position"))

      // - invalid page size
      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByDelegator(view, delegator1, 0, 0)
      }
      assertTrue(ex.getMessage.contains("Invalid page size"))

      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByDelegator(view, delegator1, 0, -1)
      }
      assertTrue(ex.getMessage.contains("Invalid page size"))

      // - null address
      assertThrows[NullPointerException] {
        getPagedForgersStakesByDelegator(view, null, 0, 2)
      }

      // we throw an exception on an empty list if we specify bad start pos
      ex = intercept[IllegalArgumentException] {
        getPagedForgersStakesByDelegator(view, new Address("0x0000000000000000000000000000000000000000"), 1, 100)
      }
      assertTrue(ex.getMessage.contains("Invalid start position"))
    }
  }

  @Test
  def testGetPagedForgerStakesLoad(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

      val rewardAddress = new Address(s"0xaabbaabbaabbaabbaabbaabbaabbaabbaabbaabb")
      val rewardShare = 0
      val epochNumber = 1000

      val numOfForgers = 43
      val numOfDelegators = 71
      val stakeAmountBigInteger = BigInteger.valueOf(1234)
      var delegator : Address = null
      var forger: ForgerPublicKeys = null
      val delegatorList : ListBuffer[Address] = ListBuffer()
      val forgerList : ListBuffer[ForgerPublicKeys] = ListBuffer()

      (0 until numOfDelegators).foreach(
        idx => {
          val postfix = f"$idx%03d"
          delegator = new Address(s"0xaaa00001230000000000deadbeefaaaa22222$postfix")
          delegatorList.append(delegator)
        }
      )

      (0 until numOfForgers).foreach(
        idx_forg => {
          val postfix = f"$idx_forg%03d"

          val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString(s"1122334455667788112233445566778811223344556677881122334455667$postfix")) // 32 bytes
          val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString(s"d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1$postfix")) // 33 bytes
          forger = ForgerPublicKeys(blockSignerProposition, vrfPublicKey)
          forgerList.append(forger)

          StakeStorage.addForger(
            view, forger.blockSignPublicKey, forger.vrfPublicKey, rewardShare,
            rewardAddress, epochNumber, delegator, stakeAmountBigInteger)


          (0 until numOfDelegators).foreach(
            idx_del => {
              StakeStorage.addStake(view, forger.blockSignPublicKey, forger.vrfPublicKey, epochNumber,
                delegatorList(idx_del), stakeAmountBigInteger)
            })
            println(s"Added $numOfDelegators delegators to forger $idx_forg")
        })



      (0 until numOfForgers).foreach(

          idx => {
          println(s"Getting stakes for forger $idx")
          val pageSize = 7
          var continue = true
          var listOfResultsByForger = Seq.empty[StakeDataDelegator]
          var startPos = 0

          while (continue) {
            val result = StakeStorage.getPagedForgersStakesByForger(view, forgerList(idx), startPos, pageSize)
            listOfResultsByForger = listOfResultsByForger ++ result.stakesData
            continue = if (result.nextStartPos != -1) {
              assertEquals(pageSize, result.stakesData.size)
              true
            }
            else
              false
            startPos = result.nextStartPos
          }
          assertEquals(numOfDelegators, listOfResultsByForger.size)
        })

      (0 until numOfDelegators).foreach(
        idx => {
          println(s"Getting stakes by delegator $idx")

          val pageSize = 13
          var continue = true
          var listOfResultsByDelegator = Seq.empty[StakeDataForger]
          var startPos = 0

          while (continue) {
            val result = StakeStorage.getPagedForgersStakesByDelegator(view, delegatorList(idx), startPos, pageSize)
            listOfResultsByDelegator = listOfResultsByDelegator ++ result.stakesData
            continue = if (result.nextStartPos != -1) {
              assertEquals(pageSize, result.stakesData.size)
              true
            }
            else
              false
            startPos = result.nextStartPos
          }
          assertEquals(numOfForgers, listOfResultsByDelegator.size)
        })

    }
  }

  @Test
  def testUpdateForger(): Unit = {
    usingView { view =>

      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93

      //  Try to update a non existing forger. It should fail
      var ex = intercept[ExecutionRevertedException] {
        StakeStorage.updateForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress)
      }
      assertEquals("Forger doesn't exist.", ex.getMessage)

      // Try to update a forger that didn't specify rewardAddress and rewardShare during registration. It should work
      val epochNumber = 135869
      val stakeAmount = BigInteger.valueOf(20000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, 0, Address.ZERO, epochNumber, delegator1, stakeAmount)
      var result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      var listOfForgers = result.forgers
      assertEquals(1, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(Address.ZERO, listOfForgers.head.rewardAddress.address())
      assertEquals(0, listOfForgers.head.rewardShare)

      // Change the reward address and share
      StakeStorage.updateForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress)
      result = StakeStorage.getPagedListOfForgers(view, 0, 10)
      listOfForgers = result.forgers
      assertEquals(1, listOfForgers.size)
      assertEquals(blockSignerProposition1, listOfForgers.head.forgerPublicKeys.blockSignPublicKey)
      assertEquals(vrfPublicKey1, listOfForgers.head.forgerPublicKeys.vrfPublicKey)
      assertEquals(rewardAddress, listOfForgers.head.rewardAddress.address())
      assertEquals(rewardShare, listOfForgers.head.rewardShare)

      // Try to change again rewardAddress and rewardShare. it should fail.
      val rewardAddress2 = new Address("0xaaa0000123000000000011112222aaaa2222aaa2")
      val rewardShare2 = 23

      ex = intercept[ExecutionRevertedException] {
        StakeStorage.updateForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare2, rewardAddress2)
      }
      assertEquals("Forger has already set reward share and reward address.", ex.getMessage)

      // Try to update a forger that didn't specify rewardAddress and rewardShare during registration. It should work
      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare2, rewardAddress2, epochNumber, delegator2, stakeAmount)

      // Change the reward address and share
      ex = intercept[ExecutionRevertedException] {
        StakeStorage.updateForger(view, blockSignerProposition2, vrfPublicKey2, rewardShare, rewardAddress)
      }
      assertEquals("Forger has already set reward share and reward address.", ex.getMessage)


    }
  }

  @Test
  def binarySearchTest(): Unit = {
    usingView { view =>
      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
      val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222111")
      val stakeAmount1 = BigInteger.valueOf(10000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, 1, rewardAddress, 130, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 160, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 190, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 220, delegator1, stakeAmount1)
      val history = StakeHistory(ForgerKey(blockSignerProposition1, vrfPublicKey1), DelegatorKey(delegator1))
      /*
        0 -> 130
        1 -> 160
        2 -> 190
        3 -> 220
       */
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, -1))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 0))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 129))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 130))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 131))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 150))
      assertEquals(0, StakeStorage.checkpointBSearch(view, history, 159))
      assertEquals(1, StakeStorage.checkpointBSearch(view, history, 160))
      assertEquals(1, StakeStorage.checkpointBSearch(view, history, 161))
      assertEquals(1, StakeStorage.checkpointBSearch(view, history, 189))
      assertEquals(2, StakeStorage.checkpointBSearch(view, history, 190))
      assertEquals(2, StakeStorage.checkpointBSearch(view, history, 191))
      assertEquals(2, StakeStorage.checkpointBSearch(view, history, 200))
      assertEquals(2, StakeStorage.checkpointBSearch(view, history, 219))
      assertEquals(3, StakeStorage.checkpointBSearch(view, history, 220))
      assertEquals(3, StakeStorage.checkpointBSearch(view, history, 221))
      assertEquals(3, StakeStorage.checkpointBSearch(view, history, Int.MaxValue))

    }
  }

  @Test
  def getForgerStakesPerEpochTest(): Unit = {
    usingView { view =>
      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
      val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222111")
      val stakeAmount1 = BigInteger.valueOf(10000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, 1, rewardAddress, 130, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 160, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 190, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 220, delegator1, stakeAmount1)
      val history = StakeHistory(ForgerKey(blockSignerProposition1, vrfPublicKey1), DelegatorKey(delegator1))

      /*
        0 -> 130 - 10000000000L
        1 -> 160 - 20000000000L
        2 -> 190 - 30000000000L
        3 -> 220 - 40000000000L
       */

      var stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 125, 129)
      assertEquals(
        Array.fill[BigInteger](5)(BigInteger.ZERO).toSeq,
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 129, 129)
      assertEquals(
        Array.fill[BigInteger](1)(BigInteger.ZERO).toSeq,
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 130, 130)
      assertEquals(
        Array.fill[BigInteger](1)(10000000000L).toSeq,
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 300, 300)
      assertEquals(
          Array.fill[BigInteger](1)(40000000000L).toSeq, //220-300
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 128, 132)
      assertEquals(
        Array.fill[BigInteger](2)(BigInteger.ZERO).toSeq ++ //128, 129
          Array.fill[BigInteger](3)(10000000000L).toSeq, //130, 131, 132
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 100, 200)
      assertEquals(
        Array.fill[BigInteger](30)(BigInteger.ZERO).toSeq ++ //100-129
          Array.fill[BigInteger](30)(10000000000L).toSeq ++ //130-159
          Array.fill[BigInteger](30)(20000000000L).toSeq ++ //160-189
          Array.fill[BigInteger](11)(30000000000L).toSeq, //190-200
        stakesPerEpoch
      )

      stakesPerEpoch = StakeStorage.getForgerStakesPerEpoch(view, history, 100, 300)
      assertEquals(
        Array.fill[BigInteger](30)(BigInteger.ZERO).toSeq ++ //100-129
          Array.fill[BigInteger](30)(10000000000L).toSeq ++ //130-159
          Array.fill[BigInteger](30)(20000000000L).toSeq ++ //160-189
          Array.fill[BigInteger](30)(30000000000L).toSeq ++ //190-219
          Array.fill[BigInteger](81)(40000000000L).toSeq, //220-300
        stakesPerEpoch
      )
    }
  }

  @Test
  def getStakeTotalTest(): Unit = {
    usingView { view =>
      createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
      val rewardAddress = new Address(s"0xaaa0000123000000000011112222aaaa22222111")
      val stakeAmount1 = BigInteger.valueOf(10000000000L)
      StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, 1, rewardAddress, 5, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 15, delegator1, stakeAmount1)
      StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, 25, delegator1, stakeAmount1)

      val rewardAddress2 = new Address(s"0xaaa0000123000000000011112222aaaa22222222")
      val stakeAmount2 = BigInteger.valueOf(100000L)
      StakeStorage.addForger(view, blockSignerProposition2, vrfPublicKey2, 1, rewardAddress2, 1, delegator2, stakeAmount2)
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, 10, delegator2, stakeAmount2)
      StakeStorage.addStake(view, blockSignerProposition2, vrfPublicKey2, 20, delegator2, stakeAmount2)

      val rewardAddress3 = new Address(s"0xaaa0000123000000000011112222aaaa22222333")
      val stakeAmount3 = BigInteger.valueOf(100L)
      StakeStorage.addForger(view, blockSignerProposition3, vrfPublicKey3, 1, rewardAddress3, 17, delegator3, stakeAmount3)
      StakeStorage.addStake(view, blockSignerProposition3, vrfPublicKey3, 27, delegator3, stakeAmount3)
      val history3 = StakeHistory(ForgerKey(blockSignerProposition3, vrfPublicKey3), DelegatorKey(delegator3))

      /*
        1 ->                100000L
        5 -> 10000000000L + 100000L
        10-> 10000000000L + 200000L
        15-> 20000000000L + 200000L
        17-> 20000000000L + 200000L + 100L
        20-> 20000000000L + 300000L + 100L
        25-> 30000000000L + 300000L + 100L
        27-> 30000000000L + 300000L + 200L
       */

      var stakePerEpoch = StakeStorage.getStakeTotal(view, None, None, 1, 30).listOfStakes
      assertEquals(
        Array.fill[BigInteger](4)(100000L).toSeq ++             //1
        Array.fill[BigInteger](5)(10000000000L + 100000L).toSeq ++        //5
        Array.fill[BigInteger](5)(10000000000L + 200000L).toSeq ++        //10
        Array.fill[BigInteger](2)(20000000000L + 200000L).toSeq ++        //15
        Array.fill[BigInteger](3)(20000000000L + 200000L + 100L).toSeq ++ //17
        Array.fill[BigInteger](5)(20000000000L + 300000L + 100L).toSeq ++ //20
        Array.fill[BigInteger](2)(30000000000L + 300000L + 100L).toSeq ++ //25
        Array.fill[BigInteger](4)(30000000000L + 300000L + 200L).toSeq    //27
        ,
        stakePerEpoch
      )

      stakePerEpoch = StakeStorage.getStakeTotal(view, Some(ForgerPublicKeys(blockSignerProposition3, vrfPublicKey3)), None, 1, 30).listOfStakes
      assertEquals(
        Array.fill[BigInteger](16)(0L).toSeq ++ //1
          Array.fill[BigInteger](10)(100L).toSeq ++       //17
          Array.fill[BigInteger](4)(200L).toSeq           //27
        ,
        stakePerEpoch
      )

      stakePerEpoch = StakeStorage.getStakeTotal(view, Some(ForgerPublicKeys(blockSignerProposition3, vrfPublicKey3)), Some(delegator1), 1, 30).listOfStakes
      assertEquals(
        Array.fill[BigInteger](30)(0L).toSeq //1
        ,
        stakePerEpoch
      )
    }
  }

  def checkStakeHistory(view: BaseAccountStateView, history: BaseStakeHistory, expectedCheckpoints: Seq[StakeCheckpoint]): Unit = {
    assertEquals(expectedCheckpoints.size, history.getSize(view))
    expectedCheckpoints.indices.foreach { idx =>
      assertEquals(expectedCheckpoints(idx), history.getCheckpoint(view, idx))
    }
    expectedCheckpoints.lastOption.foreach(checkpoint => assertEquals(checkpoint.stakedAmount, history.getLatestAmount(view)))
  }


}
