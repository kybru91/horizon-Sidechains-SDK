package io.horizen.account.state

import com.google.common.primitives.Bytes
import io.horizen.account.fork.GasFeeFork.DefaultGasFeeFork
import io.horizen.account.fork.{Version1_3_0Fork, Version1_4_0Fork}
import io.horizen.account.proposition.AddressProposition
import io.horizen.account.secret.{PrivateKeySecp256k1, PrivateKeySecp256k1Creator}
import io.horizen.account.state.ForgerStakeMsgProcessor.{AddNewStakeCmd => AddNewStakeCmdV1, GetListOfForgersCmd => GetListOfForgersCmdV1}
import io.horizen.account.state.ForgerStakeV2MsgProcessor._
import io.horizen.account.state.nativescdata.forgerstakev2.StakeStorage._
import io.horizen.account.state.nativescdata.forgerstakev2._
import io.horizen.account.state.nativescdata.forgerstakev2.events.DelegateForgerStake
import io.horizen.account.state.receipt.EthereumConsensusDataLog
import io.horizen.account.utils.ZenWeiConverter
import io.horizen.consensus.intToConsensusEpochNumber
import io.horizen.evm.{Address, Hash}
import io.horizen.fixtures.StoreFixture
import io.horizen.fork.{ForkConfigurator, ForkManagerUtil, OptionalSidechainFork, SidechainForkConsensusEpoch}
import io.horizen.params.NetworkParams
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.utils.{BytesUtils, Pair}
import org.junit.Assert._
import org.junit._
import org.mockito._
import org.scalatestplus.junit.JUnitSuite
import org.scalatestplus.mockito._
import org.web3j.abi.{FunctionReturnDecoder, TypeReference}
import org.web3j.abi.datatypes.Type
import sparkz.core.bytesToVersion
import sparkz.crypto.hash.Keccak256

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util
import java.util.Optional
import scala.collection.JavaConverters.seqAsJavaListConverter
import scala.language.implicitConversions

class ForgerStakeV2MsgProcessorTest
  extends JUnitSuite
    with MockitoSugar
    with MessageProcessorFixture
    with StoreFixture {

  val dummyBigInteger: BigInteger = BigInteger.ONE
  val negativeAmount: BigInteger = BigInteger.valueOf(-1)

  val invalidWeiAmount: BigInteger = new BigInteger("10000000001")
  val validWeiAmount: BigInteger = new BigInteger("10000000000")

  val mockNetworkParams: NetworkParams = mock[NetworkParams]
  val forgerStakeV2MessageProcessor = ForgerStakeV2MsgProcessor
  val forgerStakeMessageProcessor: ForgerStakeMsgProcessor = ForgerStakeMsgProcessor(mockNetworkParams)

  /** short hand: forger state native contract address */
  val contractAddress: Address = forgerStakeV2MessageProcessor.contractAddress

  // create private/public key pair
  val privateKey: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest".getBytes(StandardCharsets.UTF_8))
  val ownerAddressProposition: AddressProposition = privateKey.publicImage()

  val DelegateForgerStakeEventSig: Array[Byte] = getEventSignature("DelegateForgerStake(address,bytes32,bytes32,bytes1,uint256)")
  val NumOfIndexedDelegateStakeEvtParams = 3
  val RemoveForgerStakeEventSig: Array[Byte] = getEventSignature("WithdrawForgerStake(address,bytes32)")
  val NumOfIndexedRemoveForgerStakeEvtParams = 1
  val OpenForgerStakeListEventSig: Array[Byte] = getEventSignature("OpenForgerList(uint32,address,bytes32)")
  val NumOfIndexedOpenForgerStakeListEvtParams = 1
  val ActivateStakeV2EventSig: Array[Byte] = getEventSignature("ActivateStakeV2()")

  val scAddrStr1: String = "00C8F107a09cd4f463AFc2f1E6E5bF6022Ad4600"
  val scAddressObj1 = new Address("0x" + scAddrStr1)

  val V1_4_MOCK_FORK_POINT: Int = 300
  val V1_3_MOCK_FORK_POINT: Int = 200

  val blockContextForkV1_4 =  new BlockContext(
    Address.ZERO,
    0,
    0,
    DefaultGasFeeFork.blockGasLimit,
    0,
    V1_4_MOCK_FORK_POINT,
    0,
    1,
    MockedHistoryBlockHashProvider,
    Hash.ZERO
  )

  val blockContextForkV1_3 =  new BlockContext(
    Address.ZERO,
    0,
    0,
    DefaultGasFeeFork.blockGasLimit,
    0,
    V1_3_MOCK_FORK_POINT,
    0,
    1,
    MockedHistoryBlockHashProvider,
    Hash.ZERO
  )


  class TestOptionalForkConfigurator extends ForkConfigurator {
    override val fork1activation: SidechainForkConsensusEpoch = SidechainForkConsensusEpoch(0, 0, 0)
    override def getOptionalSidechainForks: util.List[Pair[SidechainForkConsensusEpoch, OptionalSidechainFork]] =
      Seq[Pair[SidechainForkConsensusEpoch, OptionalSidechainFork]](
        new Pair(SidechainForkConsensusEpoch(V1_3_MOCK_FORK_POINT, V1_3_MOCK_FORK_POINT, V1_3_MOCK_FORK_POINT), Version1_3_0Fork(true)),
        new Pair(SidechainForkConsensusEpoch(V1_4_MOCK_FORK_POINT, V1_4_MOCK_FORK_POINT, V1_4_MOCK_FORK_POINT), Version1_4_0Fork(true)),
      ).asJava
  }


  @Before
  def init(): Unit = {
    ForkManagerUtil.initializeForkManager(new TestOptionalForkConfigurator, "regtest")
    // by default start with fork active
    Mockito.when(metadataStorageView.getConsensusEpochNumber).thenReturn(Option(intToConsensusEpochNumber(V1_4_MOCK_FORK_POINT)))
  }


  def getDefaultMessage(opCode: Array[Byte], arguments: Array[Byte], nonce: BigInteger, value: BigInteger = negativeAmount): Message = {
    val data = Bytes.concat(opCode, arguments)
    new Message(
      origin,
      Optional.of(contractAddress), // to
      dummyBigInteger, // gasPrice
      dummyBigInteger, // gasFeeCap
      dummyBigInteger, // gasTipCap
      dummyBigInteger, // gasLimit
      value,
      nonce,
      data,
      false)
  }

  def randomNonce: BigInteger = randomU256


  @Test
  def testInit(): Unit = {
    usingView(forgerStakeV2MessageProcessor) { view =>
      // we have to call init beforehand
      assertTrue(forgerStakeV2MessageProcessor.isForkActive(view.getConsensusEpochNumberAsInt))
      assertFalse(view.accountExists(contractAddress))
      forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)
      assertTrue(view.accountExists(contractAddress))
      assertTrue(view.isSmartContractAccount(contractAddress))
      view.commit(bytesToVersion(getVersion.data()))
    }
  }

  @Test
  def testMethodIds(): Unit = {
    //The expected methodIds were calculated using this site: https://emn178.github.io/online-tools/keccak_256.html
    assertEquals("Wrong MethodId for activate", "0f15f4c0", ForgerStakeV2MsgProcessor.ActivateCmd)
  }


  @Test
  def testInitBeforeFork(): Unit = {

    Mockito.when(metadataStorageView.getConsensusEpochNumber).thenReturn(
      Option(intToConsensusEpochNumber(V1_4_MOCK_FORK_POINT-1)))

    usingView(forgerStakeV2MessageProcessor) { view =>

      assertFalse(view.accountExists(contractAddress))
      assertFalse(forgerStakeV2MessageProcessor.initDone(view))

      assertFalse(forgerStakeV2MessageProcessor.isForkActive(view.getConsensusEpochNumberAsInt))

      forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)

      // assert no initialization took place
      assertFalse(view.accountExists(contractAddress))
      assertFalse(forgerStakeV2MessageProcessor.initDone(view))
    }
  }


  @Test
  def testDoubleInit(): Unit = {

    usingView(forgerStakeV2MessageProcessor) { view =>

      assertTrue(forgerStakeV2MessageProcessor.isForkActive(view.getConsensusEpochNumberAsInt))

      assertFalse(view.accountExists(contractAddress))
      assertFalse(forgerStakeV2MessageProcessor.initDone(view))

      forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)

      assertTrue(view.accountExists(contractAddress))
      assertTrue(forgerStakeV2MessageProcessor.initDone(view))

      view.commit(bytesToVersion(getVersion.data()))

      val ex = intercept[MessageProcessorInitializationException] {
        forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)
      }
      assertTrue(ex.getMessage.contains("already init"))
    }
  }


  @Test
  def testCanProcess(): Unit = {
    usingView(forgerStakeV2MessageProcessor) { view =>

      // assert no initialization took place yet
      assertFalse(view.accountExists(contractAddress))
      assertFalse(forgerStakeV2MessageProcessor.initDone(view))

      assertTrue(forgerStakeV2MessageProcessor.isForkActive(view.getConsensusEpochNumberAsInt))

      // correct contract address
      assertTrue(TestContext.canProcess(forgerStakeV2MessageProcessor, getMessage(forgerStakeV2MessageProcessor.contractAddress), view, view.getConsensusEpochNumberAsInt))

      // check initialization took place
      assertTrue(view.accountExists(contractAddress))
      assertTrue(view.isSmartContractAccount(contractAddress))
      assertFalse(view.isEoaAccount(contractAddress))

      // call a second time for checking it does not do init twice (would assert)
      assertTrue(TestContext.canProcess(forgerStakeV2MessageProcessor, getMessage(forgerStakeV2MessageProcessor.contractAddress), view, view.getConsensusEpochNumberAsInt))

      // wrong address
      assertFalse(TestContext.canProcess(forgerStakeV2MessageProcessor, getMessage(randomAddress), view, view.getConsensusEpochNumberAsInt))
      // contract deployment: to == null
      assertFalse(TestContext.canProcess(forgerStakeV2MessageProcessor, getMessage(null), view, view.getConsensusEpochNumberAsInt))

      view.commit(bytesToVersion(getVersion.data()))
    }
  }

  @Test
  def testCanNotProcessBeforeFork(): Unit = {

    Mockito.when(metadataStorageView.getConsensusEpochNumber).thenReturn(
      Option(intToConsensusEpochNumber(1)))

    usingView(forgerStakeV2MessageProcessor) { view =>

      // create sender account with some fund in it
      val initialAmount = BigInteger.valueOf(100).multiply(validWeiAmount)
      val txHash1 = Keccak256.hash("tx")
      view.setupTxContext(txHash1, 10)
      createSenderAccount(view, initialAmount, scAddressObj1)


      assertFalse(forgerStakeV2MessageProcessor.isForkActive(view.getConsensusEpochNumberAsInt))

      // correct contract address and message but fork not yet reached
      assertFalse(TestContext.canProcess(forgerStakeV2MessageProcessor, getMessage(forgerStakeV2MessageProcessor.contractAddress), view, view.getConsensusEpochNumberAsInt))

      // the init did not take place
      assertFalse(view.accountExists(contractAddress))
      assertFalse(forgerStakeV2MessageProcessor.initDone(view))

      view.commit(bytesToVersion(getVersion.data()))
    }
  }

  @Test
  def testActivateBase(): Unit = {

    val processors = Seq(forgerStakeV2MessageProcessor, forgerStakeMessageProcessor)
    usingView(processors) { view =>
      // Initialize old forger stake directly in V2. The upgrade is made automatically in the init, in this case.
      forgerStakeMessageProcessor.init(view, V1_3_MOCK_FORK_POINT)
      assertEquals(ForgerStakeStorageVersion.VERSION_2, ForgerStakeStorage.getStorageVersionFromDb(view))

      forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)

      // create sender account with some fund in it
      val initialAmount = BigInteger.valueOf(10).multiply(ZenWeiConverter.MAX_MONEY_IN_WEI)
      createSenderAccount(view, initialAmount)

      val nonce = 0

      // Test "activate" before reaching the fork point. It should fail.

      var msg = getMessage(
        contractAddress, 0, BytesUtils.fromHexString(ActivateCmd), nonce, ownerAddressProposition.address())

      // should fail because, before Version 1.4 fork, ActivateCmd is not a valid function signature
      val blockContextBeforeFork = new BlockContext(
        Address.ZERO,
        0,
        0,
        DefaultGasFeeFork.blockGasLimit,
        0,
        V1_4_MOCK_FORK_POINT - 1,
        0,
        1,
        MockedHistoryBlockHashProvider,
        Hash.ZERO
      )

      var exc = intercept[ExecutionRevertedException] {
        assertGas(0, msg, view, forgerStakeV2MessageProcessor, blockContextBeforeFork)
      }
      assertTrue(exc.getMessage.contains("fork not active"))
      assertEquals(ForgerStakeStorageVersion.VERSION_2, ForgerStakeStorage.getStorageVersionFromDb(view))


      // Test after fork.

      //Setting the context
      val txHash1 = Keccak256.hash("first tx")
      view.setupTxContext(txHash1, 10)

      assertGasInterop(0, msg, view, processors, blockContextForkV1_4)

      // Checking log
      val listOfLogs = view.getLogs(txHash1)
      checkActivateEvents(listOfLogs)

      // Check that old forger stake message processor cannot be used anymore

      msg = getMessage(forgerStakeMessageProcessor.contractAddress, 0, BytesUtils.fromHexString(GetListOfForgersCmdV1), randomNonce)
      exc = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeMessageProcessor, msg, view, blockContextForkV1_4, _))
      }
      assertTrue(s"Wrong error message ${exc.getMessage}", exc.getMessage.contains("disabled"))


      // Negative tests
      msg = getMessage(
        contractAddress, 0, BytesUtils.fromHexString(ActivateCmd), nonce, ownerAddressProposition.address())
      // Check that it cannot be called twice
      exc = intercept[ExecutionRevertedException] {
        assertGasInterop(0, msg, view, processors, blockContextForkV1_4)
      }
      assertEquals(s"Forger stake V2 already activated", exc.getMessage)

      // Check that it is not payable
      val value = validWeiAmount
      msg = getMessage(
        contractAddress, value, BytesUtils.fromHexString(ActivateCmd), nonce, ownerAddressProposition.address())

      val excPayable = intercept[ExecutionRevertedException] {
        assertGasInterop(0, msg, view, processors, blockContextForkV1_4)
      }
      assertEquals("Call value must be zero", excPayable.getMessage)

       // try processing a msg with a trailing byte in the arguments
      val badData = new Array[Byte](1)
      val msgBad = getMessage(contractAddress, 0, BytesUtils.fromHexString(ActivateCmd) ++ badData, randomNonce)

      // should fail because input has a trailing byte
      exc = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeV2MessageProcessor, msgBad, view, blockContextForkV1_4, _))
      }
      assertTrue(s"Wrong exc message: ${exc.getMessage}, expected:invalid msg data length", exc.getMessage.contains("invalid msg data length"))
      view.commit(bytesToVersion(getVersion.data()))
    }
  }

  @Test
  def testActivate(): Unit = {
    val processors = Seq(forgerStakeV2MessageProcessor, forgerStakeMessageProcessor)
    usingView(processors) { view =>

      forgerStakeMessageProcessor.init(view, V1_3_MOCK_FORK_POINT)

      // create sender account with some fund in it
      val initialAmount = ZenWeiConverter.MAX_MONEY_IN_WEI
      createSenderAccount(view, initialAmount)

      val listOfExpectedResults = (1 to 5).map {idx =>

        val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString(s"112233445566778811223344556677881122334455667788112233445566778$idx")) // 32 bytes
        val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString(s"d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d118$idx")) // 33 bytes

        Mockito.when(mockNetworkParams.restrictForgers).thenReturn(true)
        Mockito.when(mockNetworkParams.allowedForgersList).thenReturn(Seq((blockSignerProposition, vrfPublicKey)))

        // Create some stakes with old storage model
        val privateKey1: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest1".getBytes(StandardCharsets.UTF_8))
        val owner1: AddressProposition = privateKey1.publicImage()
        val amount1 = addStakesV2(view, blockSignerProposition, vrfPublicKey, owner1, 40, blockContextForkV1_3)

        val privateKey2: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest2".getBytes(StandardCharsets.UTF_8))
        val owner2: AddressProposition = privateKey2.publicImage()
        val amount2 = addStakesV2(view, blockSignerProposition, vrfPublicKey, owner2, 50, blockContextForkV1_3)

        val privateKey3: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest3".getBytes(StandardCharsets.UTF_8))
        val owner3: AddressProposition = privateKey3.publicImage()
        val amount3 = addStakesV2(view, blockSignerProposition, vrfPublicKey, owner3, 100, blockContextForkV1_3)
        val listOfStakes = (owner3, amount3) :: (owner2, amount2) :: (owner1, amount1) :: Nil
        (ForgerPublicKeys(blockSignerProposition, vrfPublicKey), listOfStakes)
      }
      //Setting the context
      val txHash1 = Keccak256.hash("first tx")
      view.setupTxContext(txHash1, 10)

      val activateMsg = getMessage(
        contractAddress, 0, BytesUtils.fromHexString(ActivateCmd), randomNonce, ownerAddressProposition.address())
      assertGasInterop(0, activateMsg, view, processors, blockContextForkV1_4)

      val listOfStakes = StakeStorage.getAllForgerStakes(view)
      val expNumOfStakes = listOfExpectedResults.foldLeft(0){(sum, res) => sum + res._2.size }
      assertEquals(expNumOfStakes, listOfStakes.size)

      listOfExpectedResults.foreach{ case (forgerKeys, expListOfStakes) =>
        val forgerOpt = StakeStorage.getForger(view, forgerKeys.blockSignPublicKey, forgerKeys.vrfPublicKey)
        assertFalse(forgerOpt.isEmpty)
        assertEquals(forgerKeys.blockSignPublicKey, forgerOpt.get.forgerPublicKeys.blockSignPublicKey)
        assertEquals(forgerKeys.vrfPublicKey, forgerOpt.get.forgerPublicKeys.vrfPublicKey)
        assertEquals(0, forgerOpt.get.rewardShare)
        assertEquals(Address.ZERO, forgerOpt.get.rewardAddress.address())

        val forgerKey = ForgerKey(forgerKeys.blockSignPublicKey, forgerKeys.vrfPublicKey)
        val forgerHistory = ForgerStakeHistory(forgerKey)
        assertEquals(1, forgerHistory.getSize(view))
        assertEquals(blockContextForkV1_4.consensusEpochNumber, forgerHistory.getCheckpoint(view, 0).fromEpochNumber)
        assertEquals(expListOfStakes.foldLeft(BigInteger.ZERO){(sum, pair) => sum.add(pair._2)}, forgerHistory.getCheckpoint(view, 0).stakedAmount)

        val listOfDelegators = DelegatorList(forgerKey)
        assertEquals(expListOfStakes.size, listOfDelegators.getSize(view))

        expListOfStakes.foreach{ case (expDelegator, expAmount) =>
          val stake1 = listOfStakes.find(stake => (stake.ownerPublicKey == expDelegator) && (stake.forgerPublicKeys == forgerKeys))
          assertTrue(stake1.isDefined)
          assertEquals(expAmount, stake1.get.stakedAmount)
          assertEquals(forgerOpt.get.forgerPublicKeys, stake1.get.forgerPublicKeys)
          val stakeHistory = StakeHistory(forgerKey, DelegatorKey(expDelegator.address()))
          assertEquals(1, stakeHistory.getSize(view))
          assertEquals(blockContextForkV1_4.consensusEpochNumber, stakeHistory.getCheckpoint(view, 0).fromEpochNumber)
          assertEquals(expAmount, stakeHistory.getCheckpoint(view, 0).stakedAmount)

        }

      }

      // Checking log
      val listOfLogs = view.getLogs(txHash1)
     checkActivateEvents(listOfLogs)

      view.commit(bytesToVersion(getVersion.data()))

    }
  }

  def getBlockContextForEpoch(epochNum: Int): BlockContext = new BlockContext(
    Address.ZERO,
    0,
    0,
    DefaultGasFeeFork.blockGasLimit,
    0,
    epochNum,
    0,
    1,
    MockedHistoryBlockHashProvider,
    Hash.ZERO
  )

  @Test
  def testAddAndRemoveStake(): Unit = {

    val processors = Seq(forgerStakeV2MessageProcessor, forgerStakeMessageProcessor)

    usingView(processors) { view =>
      forgerStakeMessageProcessor.init(view, V1_3_MOCK_FORK_POINT)

      forgerStakeV2MessageProcessor.init(view, view.getConsensusEpochNumberAsInt)

      // create sender account with some fund in it
      val initialAmount = BigInteger.valueOf(100).multiply(validWeiAmount)
      createSenderAccount(view, initialAmount)

      //Setting the context

      val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString("1122334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
      val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString("d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes

      val delegateCmdInput = DelegateCmdInput(
        ForgerPublicKeys(blockSignerProposition, vrfPublicKey)
      )

      val delegateData: Array[Byte] = BytesUtils.fromHexString(DelegateCmd) ++ delegateCmdInput.encode()
      var msg = getMessage(contractAddress, validWeiAmount,  delegateData, randomNonce)

      // Check that delegate and withdraw cannot be called before activate

      var exc = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeV2MessageProcessor, msg, view, blockContextForkV1_4, _))
      }
      var expectedErr = "Forger stake V2 has not been activated yet"
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      val withdrawCmdInput = WithdrawCmdInput(
        ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
        BigInteger.ONE
      )

      msg = getMessage(contractAddress, BigInteger.ZERO, BytesUtils.fromHexString(WithdrawCmd) ++ withdrawCmdInput.encode(), randomNonce)
      exc = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeV2MessageProcessor, msg, view, blockContextForkV1_4, _))
      }
      assertTrue(exc.getMessage.contains("Forger stake V2 has not been activated yet"))

      // Call activate

      val initialOwnerBalance = BigInteger.valueOf(200).multiply(validWeiAmount)
      createSenderAccount(view, initialOwnerBalance, ownerAddressProposition.address())

      msg = getMessage(
        contractAddress, 0, BytesUtils.fromHexString(ActivateCmd), randomNonce, ownerAddressProposition.address())

      assertGasInterop(0, msg, view, processors, blockContextForkV1_4)

      // Try delegate to a non-existing forger. It should fail.
      msg = getMessage(contractAddress, validWeiAmount, delegateData, randomNonce)
      exc = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeV2MessageProcessor, msg, view, blockContextForkV1_4, _))
      }
      expectedErr = "Forger doesn't exist."
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      // Register the forger
      val initialStake = new BigInteger("1000000000000")
      StakeStorage.addForger(view, delegateCmdInput.forgerPublicKeys.blockSignPublicKey, delegateCmdInput.forgerPublicKeys.vrfPublicKey,
        0, Address.ZERO, blockContextForkV1_4.consensusEpochNumber, ownerAddressProposition.address(), initialStake)

      // Add the first stake
      val txHash1 = Keccak256.hash("first tx")
      view.setupTxContext(txHash1, 10)

      var stakeAmount = validWeiAmount
      msg = getMessage(contractAddress, stakeAmount, delegateData, randomNonce, ownerAddressProposition.address())
      assertGas(13587, msg, view, forgerStakeV2MessageProcessor, blockContextForkV1_4)
      // Check that the balances of the delegator and of the forger smart contract have changed

      var listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(1, listOfStakes.size)
      assertEquals(delegateCmdInput.forgerPublicKeys, listOfStakes.head.forgerPublicKeys)
      assertEquals(ownerAddressProposition, listOfStakes.head.ownerPublicKey)
      var expectedOwnerStakeAmount = initialStake.add(stakeAmount)
      assertEquals(expectedOwnerStakeAmount, listOfStakes.head.stakedAmount)

      var expectedOwnerBalance = initialOwnerBalance.subtract(stakeAmount)
      assertEquals(expectedOwnerBalance, view.getBalance(ownerAddressProposition.address()))
      var expectedForgerContractBalance = stakeAmount
      assertEquals(expectedForgerContractBalance, view.getBalance(contractAddress))

      // Check log event
      var listOfLogs = view.getLogs(txHash1)
      assertEquals("Wrong number of logs", 1, listOfLogs.length)
      var expectedEvent = DelegateForgerStake(ownerAddressProposition.address(), delegateCmdInput.forgerPublicKeys.blockSignPublicKey,
        delegateCmdInput.forgerPublicKeys.vrfPublicKey, stakeAmount)

      checkDelegateForgerStakeEvent(expectedEvent, listOfLogs(0))


      // Add with same delegator but different epoch
      val txHash2 = Keccak256.hash("tx2")
      view.setupTxContext(txHash2, 10)
      stakeAmount = validWeiAmount.multiply(2)

      var blockContext = getBlockContextForEpoch(V1_4_MOCK_FORK_POINT + 1)

      msg = getMessage(contractAddress, stakeAmount, delegateData, randomNonce, ownerAddressProposition.address())
      assertGas(57787, msg, view, forgerStakeV2MessageProcessor, blockContext)

      expectedOwnerBalance = expectedOwnerBalance.subtract(stakeAmount)
      assertEquals(expectedOwnerBalance, view.getBalance(ownerAddressProposition.address()))

      expectedForgerContractBalance = expectedForgerContractBalance.add(stakeAmount)
      assertEquals(expectedForgerContractBalance, view.getBalance(contractAddress))

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(1, listOfStakes.size)
      assertEquals(delegateCmdInput.forgerPublicKeys, listOfStakes.head.forgerPublicKeys)
      assertEquals(ownerAddressProposition, listOfStakes.head.ownerPublicKey)
      expectedOwnerStakeAmount = expectedOwnerStakeAmount.add(stakeAmount)
      assertEquals(expectedOwnerStakeAmount, listOfStakes.head.stakedAmount)

      // Check log event
      listOfLogs = view.getLogs(txHash2)
      assertEquals("Wrong number of logs", 1, listOfLogs.length)
      expectedEvent = DelegateForgerStake(ownerAddressProposition.address(), delegateCmdInput.forgerPublicKeys.blockSignPublicKey,
        delegateCmdInput.forgerPublicKeys.vrfPublicKey, stakeAmount)

      checkDelegateForgerStakeEvent(expectedEvent, listOfLogs(0))

      // Add with different delegator but same epoch
      val privateKey1: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest1".getBytes(StandardCharsets.UTF_8))
      val owner1: AddressProposition = privateKey1.publicImage()

      val initialOwner1Balance = BigInteger.valueOf(200).multiply(validWeiAmount)
      createSenderAccount(view, initialOwner1Balance, owner1.address())

      val txHash3 = Keccak256.hash("tx3")
      view.setupTxContext(txHash3, 10)
      stakeAmount = validWeiAmount.multiply(3)

      msg = getMessage(contractAddress, stakeAmount, delegateData, randomNonce, owner1.address())
      assertGas(124087, msg, view, forgerStakeV2MessageProcessor, blockContext)

      assertEquals(expectedOwnerBalance, view.getBalance(ownerAddressProposition.address()))
      expectedForgerContractBalance = expectedForgerContractBalance.add(stakeAmount)
      assertEquals(expectedForgerContractBalance, view.getBalance(contractAddress))

      val expectedOwner1Balance = initialOwner1Balance.subtract(stakeAmount)
      assertEquals(expectedOwner1Balance, view.getBalance(owner1.address()))

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(2, listOfStakes.size)
      assertEquals(delegateCmdInput.forgerPublicKeys, listOfStakes.head.forgerPublicKeys)
      assertEquals(ownerAddressProposition, listOfStakes.head.ownerPublicKey)
      assertEquals(expectedOwnerStakeAmount, listOfStakes.head.stakedAmount)
      assertEquals(owner1, listOfStakes(1).ownerPublicKey)
      val expectedOwner1StakeAmount = stakeAmount
      assertEquals(expectedOwner1StakeAmount, listOfStakes(1).stakedAmount)

      // Check log event
      listOfLogs = view.getLogs(txHash3)
      assertEquals("Wrong number of logs", 1, listOfLogs.length)
      expectedEvent = DelegateForgerStake(owner1.address(), delegateCmdInput.forgerPublicKeys.blockSignPublicKey,
        delegateCmdInput.forgerPublicKeys.vrfPublicKey, stakeAmount)


      // Add with different delegator and different epoch
      val txHash4 = Keccak256.hash("tx4")
      view.setupTxContext(txHash4, 10)
      stakeAmount = validWeiAmount

      val privateKey2: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest2".getBytes(StandardCharsets.UTF_8))
      val owner2: AddressProposition = privateKey2.publicImage()

      blockContext = getBlockContextForEpoch(blockContext.consensusEpochNumber + 1)
      val initialOwner2Balance = BigInteger.valueOf(300).multiply(validWeiAmount)
      createSenderAccount(view, initialOwner2Balance, owner2.address())

      msg = getMessage(contractAddress, stakeAmount, delegateData, randomNonce, owner2.address())
      assertGas(144087, msg, view, forgerStakeV2MessageProcessor, blockContext)

      listOfStakes = StakeStorage.getAllForgerStakes(view)
      assertEquals(3, listOfStakes.size)
      assertEquals(delegateCmdInput.forgerPublicKeys, listOfStakes.head.forgerPublicKeys)
      assertEquals(ownerAddressProposition, listOfStakes.head.ownerPublicKey)
      assertEquals(expectedOwnerStakeAmount, listOfStakes.head.stakedAmount)
      assertEquals(owner1, listOfStakes(1).ownerPublicKey)
      assertEquals(expectedOwner1StakeAmount, listOfStakes(1).stakedAmount)
      assertEquals(owner2, listOfStakes(2).ownerPublicKey)
      val expectedOwner2StakeAmount = stakeAmount
      assertEquals(expectedOwner2StakeAmount, listOfStakes(2).stakedAmount)

      assertEquals(expectedOwnerBalance, view.getBalance(ownerAddressProposition.address()))
      expectedForgerContractBalance = expectedForgerContractBalance.add(stakeAmount)
      assertEquals(expectedForgerContractBalance, view.getBalance(contractAddress))
      assertEquals(expectedOwner1Balance, view.getBalance(owner1.address()))

      val expectedOwner2Balance = initialOwner2Balance.subtract(stakeAmount)
      assertEquals(expectedOwner2Balance, view.getBalance(owner2.address()))

      // Check log event
      listOfLogs = view.getLogs(txHash4)
      assertEquals("Wrong number of logs", 1, listOfLogs.length)
      expectedEvent = DelegateForgerStake(owner2.address(), delegateCmdInput.forgerPublicKeys.blockSignPublicKey,
        delegateCmdInput.forgerPublicKeys.vrfPublicKey, stakeAmount)

      //////////////////////////////////////////////////////////
      // Negative tests
      //////////////////////////////////////////////////////////

      // Add stake without enough balance

      val privateKey3: PrivateKeySecp256k1 = PrivateKeySecp256k1Creator.getInstance().generateSecret("nativemsgprocessortest3".getBytes(StandardCharsets.UTF_8))
      val owner3: AddressProposition = privateKey3.publicImage()
      assertEquals(BigInteger.ZERO, view.getBalance(owner3.address()))

      msg = getMessage(contractAddress, validWeiAmount, delegateData, randomNonce, owner3.address())
      exc = intercept[ExecutionRevertedException] {
        assertGas(2300, msg, view, forgerStakeV2MessageProcessor, blockContext)
      }
      expectedErr = "Insufficient funds."
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      // Add Stake with value 0.

      msg = getMessage(contractAddress, BigInteger.ZERO, delegateData, randomNonce, owner2.address())
      exc = intercept[ExecutionRevertedException] {
        assertGas(2100, msg, view, forgerStakeV2MessageProcessor, blockContext)
      }
      expectedErr = "Value must not be zero"
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      // Add Stake with invalid zen amount.

      msg = getMessage(contractAddress, invalidWeiAmount, delegateData, randomNonce, owner2.address())
      exc = intercept[ExecutionRevertedException] {
        assertGas(2100, msg, view, forgerStakeV2MessageProcessor, blockContext)
      }
      expectedErr = "Value is not a legal wei amount"
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      // Add Stake in a epoch in the past.

      blockContext = getBlockContextForEpoch(blockContext.consensusEpochNumber - 1)
      msg = getMessage(contractAddress, validWeiAmount, delegateData, randomNonce, owner2.address())
      exc = intercept[ExecutionRevertedException] {
        assertGas(6400, msg, view, forgerStakeV2MessageProcessor, blockContext)
      }
      expectedErr = "Epoch is in the past"
      assertTrue(s"Wrong error message, expected $expectedErr, got: ${exc.getMessage}", exc.getMessage.contains(expectedErr))

      // try processing a msg with a trailing byte in the arguments
      val badData = Bytes.concat(delegateData, new Array[Byte](1))
      val msgBad = getMessage(contractAddress, stakeAmount, badData, randomNonce)

      // should fail because input has a trailing byte
      blockContext = getBlockContextForEpoch(blockContext.consensusEpochNumber + 10)
      val ex = intercept[ExecutionRevertedException] {
        withGas(TestContext.process(forgerStakeV2MessageProcessor, msgBad, view, blockContext, _))
      }
      assertTrue(ex.getMessage.contains("Wrong message data field length"))

      // withdraw tests:
      // - value <= 0
      // - invalid wei //TODO che succede con un invalid wei amount? Non dovrebbe essere possibile
      //- forge non esiste
      //- delegator non esiste
      stakeAmount = validWeiAmount
      var withdrawInput = WithdrawCmdInput(
        ForgerPublicKeys(blockSignerProposition, vrfPublicKey), stakeAmount
      )
//
//      val data2: Array[Byte] = withdrawInput.encode()
//      val msg2 = getMessage(contractAddress, validWeiAmount, BytesUtils.fromHexString(WithdrawCmd) ++ data2, randomNonce)
//
//      val returnData2 = assertGas(0, msg2, view, forgerStakeV2MessageProcessor, blockContextForkV1_4)
//      assertNotNull(returnData2)
//      println("This is the returned value: " + BytesUtils.toHexString(returnData2))
//
//      //TODO: add checks...
//
//      //stake total
//
//      val stakeTotalInput = StakeTotalCmdInput(
//        ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
//        scAddressObj1,
//        5,
//        5
//      )
//
//      val data3: Array[Byte] = stakeTotalInput.encode()
//      val msg3 = getMessage(contractAddress, validWeiAmount, BytesUtils.fromHexString(StakeTotalCmd) ++ data3, randomNonce)
//      val returnData3= assertGas(0, msg2, view, forgerStakeV2MessageProcessor, blockContextForkV1_4)
//      assertNotNull(returnData3)
//      println("This is the returned value: " + BytesUtils.toHexString(returnData2))
//
//      //TODO: add checks...
//
//      //GetPagedForgersStakesByForger
//
//      val pagedForgersStakesByForgerCmd = PagedForgersStakesByForgerCmdInput(
//        ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
//        5,
//        5
//      )
//
//      val data4: Array[Byte] = pagedForgersStakesByForgerCmd.encode()
//      val msg4 = getMessage(contractAddress, validWeiAmount, BytesUtils.fromHexString(GetPagedForgersStakesByForgerCmd) ++ data3, randomNonce)
//      val returnData4 = assertGas(0, msg2, view, forgerStakeV2MessageProcessor, blockContextForkV1_4)
//      assertNotNull(returnData4)
//      println("This is the returned value: " + BytesUtils.toHexString(returnData2))
//
//      //TODO: add checks...
//
//      //GetPagedForgersStakesByDelegator
//
//      val pagedForgersStakesByDelegatorCmd = PagedForgersStakesByDelegatorCmdInput(
//        scAddressObj1,
//        5,
//        5
//      )
//
//      val data5: Array[Byte] = pagedForgersStakesByDelegatorCmd.encode()
//      val msg5 = getMessage(contractAddress, validWeiAmount, BytesUtils.fromHexString(GetPagedForgersStakesByDelegatorCmd) ++ data5, randomNonce)
//      val returnData5 = assertGas(0, msg5, view, forgerStakeV2MessageProcessor, blockContextForkV1_4)
//      assertNotNull(returnData5)
//      println("This is the returned value: " + BytesUtils.toHexString(returnData2))
//
//      //TODO: add checks...
    }
  }

  def checkActivateEvents(listOfLogs: Array[EthereumConsensusDataLog]): Unit = {
    assertEquals("Wrong number of logs", 2, listOfLogs.length)

    assertEquals("Wrong address", forgerStakeMessageProcessor.contractAddress, listOfLogs.head.address)
    assertArrayEquals("Wrong event signature", getEventSignature("DisableStakeV1()"), listOfLogs.head.topics(0).toBytes)

    assertEquals("Wrong address", contractAddress, listOfLogs(1).address)
    assertEquals("Wrong number of topics", 1, listOfLogs(1).topics.length) //The first topic is the hash of the signature of the event
    assertArrayEquals("Wrong event signature", ActivateStakeV2EventSig, listOfLogs(1).topics(0).toBytes)

  }


  def checkDelegateForgerStakeEvent(expectedEvent: DelegateForgerStake, actualEvent: EthereumConsensusDataLog): Unit = {
    assertEquals("Wrong address", contractAddress, actualEvent.address)
    assertEquals("Wrong number of topics", NumOfIndexedDelegateStakeEvtParams + 1, actualEvent.topics.length) //The first topic is the hash of the signature of the event
    assertArrayEquals("Wrong event signature", DelegateForgerStakeEventSig, actualEvent.topics(0).toBytes)
    assertEquals("Wrong sender address in topic", expectedEvent.sender, decodeEventTopic(actualEvent.topics(1), TypeReference.makeTypeReference(expectedEvent.sender.getTypeAsString)))
    assertEquals("Wrong vrfKey1 in topic", expectedEvent.vrf1, decodeEventTopic(actualEvent.topics(2), TypeReference.makeTypeReference(expectedEvent.vrf1.getTypeAsString)))
    assertEquals("Wrong vrfKey2 in topic", expectedEvent.vrf2, decodeEventTopic(actualEvent.topics(3), TypeReference.makeTypeReference(expectedEvent.vrf2.getTypeAsString)))

    val listOfRefs = util.Arrays.asList(
        TypeReference.makeTypeReference(expectedEvent.signPubKey.getTypeAsString),
        TypeReference.makeTypeReference(expectedEvent.value.getTypeAsString))
      .asInstanceOf[util.List[TypeReference[Type[_]]]]
    val listOfDecodedData = FunctionReturnDecoder.decode(BytesUtils.toHexString(actualEvent.data), listOfRefs)
    assertEquals("Wrong signPubKey in data", expectedEvent.signPubKey, listOfDecodedData.get(0))
    assertEquals("Wrong amount in data", expectedEvent.value.getValue, listOfDecodedData.get(1).getValue)
  }


  private def addStakesV2(view: AccountStateView,
                        blockSignerProposition: PublicKey25519Proposition,
                        vrfPublicKey: VrfPublicKey,
                        ownerAddressProposition1: AddressProposition,
                        numOfStakes: Int,
                        blockContext: BlockContext): BigInteger = {
    val cmdInput1 = AddNewStakeCmdInput(
      ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
      ownerAddressProposition1.address()
    )
    val data: Array[Byte] = cmdInput1.encode()

    var listOfForgerStakes = Seq[AccountForgingStakeInfo]()

    var totalAmount = BigInteger.ZERO
    for (i <- 1 to numOfStakes) {
      val stakeAmount = validWeiAmount.multiply(BigInteger.valueOf(i))
      val nonce = randomNonce
      val msg = getMessage(contractAddress, stakeAmount,
        BytesUtils.fromHexString(AddNewStakeCmdV1) ++ data, nonce)
      val expStakeId = forgerStakeMessageProcessor.getStakeId(msg)
      listOfForgerStakes = listOfForgerStakes :+ AccountForgingStakeInfo(expStakeId,
        ForgerStakeData(ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
          ownerAddressProposition1, stakeAmount))
      val returnData = withGas(TestContext.process(forgerStakeMessageProcessor, msg, view, blockContext, _))
      assertNotNull(returnData)
      totalAmount = totalAmount.add(stakeAmount)
    }
    totalAmount
  }

}


