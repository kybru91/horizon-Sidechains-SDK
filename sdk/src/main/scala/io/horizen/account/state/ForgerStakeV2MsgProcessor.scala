package io.horizen.account.state

import com.horizen.librustsidechains.Constants
import io.horizen.account.abi.ABIUtil.{METHOD_ID_LENGTH, getABIMethodId, getArgumentsFromData, getFunctionSignature}
import io.horizen.account.fork.Version1_4_0Fork
import io.horizen.account.state.events.ActivateStakeV2
import io.horizen.account.state.nativescdata.forgerstakev2.StakeStorage.{addForger, getForger}
import io.horizen.account.state.nativescdata.forgerstakev2._
import io.horizen.account.utils.WellKnownAddresses.{FORGER_STAKE_SMART_CONTRACT_ADDRESS, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS}
import io.horizen.account.utils.ZenWeiConverter.isValidZenAmount
import io.horizen.consensus.generateHashAndCleanUp
import io.horizen.evm.Address
import io.horizen.params.NetworkParams
import io.horizen.account.utils.ZenWeiConverter.{convertWeiToZennies, convertZenniesToWei, isValidZenAmount}
import io.horizen.consensus.generateHashAndCleanUp
import io.horizen.evm.Address
import io.horizen.proof.{Signature25519, VrfProof}
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.utils.BytesUtils
import org.web3j.crypto.Keys
import sparkz.crypto.hash.Keccak256

import java.math.BigInteger
import java.nio.charset.StandardCharsets

trait ForgerStakesV2Provider {
  private[horizen] def getPagedForgersStakesByForger(view: BaseAccountStateView, forger: ForgerPublicKeys, startPos: Int, pageSize: Int): PagedStakesByForgerResponse
  private[horizen] def getPagedForgersStakesByDelegator(view: BaseAccountStateView, delegator: Address, startPos: Int, pageSize: Int): PagedStakesByDelegatorResponse
}

case class ForgerStakeV2MsgProcessor(networkParams: NetworkParams) extends NativeSmartContractWithFork with ForgerStakesV2Provider {
  override val contractAddress: Address = FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
  override val contractCode: Array[Byte] = Keccak256.hash("ForgerStakeV2SmartContractCode")

  val MAX_REWARD_SHARE = 1000
  val MIN_REGISTER_FORGER_STAKED_AMOUNT_IN_WEI = BigInteger.TEN.pow(18).multiply(BigInteger.TEN) // 10 Zen

  override def isForkActive(consensusEpochNumber: Int): Boolean = {
    Version1_4_0Fork.get(consensusEpochNumber).active
  }

  override def process(invocation: Invocation, view: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {
    if (!Version1_4_0Fork.get(context.blockContext.consensusEpochNumber).active)
      throw new ExecutionRevertedException(s"fork not active")
    val gasView = view.getGasTrackedView(invocation.gasPool)
    getFunctionSignature(invocation.input) match {
      case RegisterForgerCmd =>
        doRegisterForger(invocation, gasView, context)
      case DelegateCmd =>
        doDelegateCmd(invocation, gasView, context.msg)
      case WithdrawCmd =>
        doWithdrawCmd(invocation, gasView, context.msg)
      case StakeTotalCmd =>
        doStakeTotalCmd(invocation, gasView, context.msg)
      case GetPagedForgersStakesByForgerCmd =>
        doPagedForgersStakesByForgerCmd(invocation, gasView, context.msg)
      case GetPagedForgersStakesByDelegatorCmd =>
        doPagedForgersStakesByDelegatorCmd(invocation, gasView, context.msg)
      case ActivateCmd =>
        doActivateCmd(invocation, view, context) // That shouldn't consume gas, so it doesn't use gasView
      case opCodeHex => throw new ExecutionRevertedException(s"op code not supported: $opCodeHex")
    }
  }


  def getHashedMessageToSign(blockSignPubKeyStr: String, vrfPublicKeyStr: String, rewardShare: Int, smartcontract_address: String) : Array[Byte] = {
    val messageToSignString = blockSignPubKeyStr + vrfPublicKeyStr + rewardShare.toString + Keys.toChecksumAddress(smartcontract_address)

    val chunks = messageToSignString.getBytes(StandardCharsets.UTF_8).grouped(Constants.FIELD_ELEMENT_LENGTH-1).toArray

    generateHashAndCleanUp(chunks:_*)
  }

  def verifySignatures(msgToSign: Array[Byte], blockSignPubKey: PublicKey25519Proposition, vrfPubKey: VrfPublicKey, sign25519: Signature25519, signVrf: VrfProof): Unit = {
    if (!sign25519.isValid(blockSignPubKey, msgToSign)) {
      val errMsg = s"Invalid signature, could not validate against blockSignerProposition=$blockSignPubKey"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }

    if (!signVrf.isValid(vrfPubKey, msgToSign)) {
      val errMsg = s"Invalid signature, could not validate against vrfKey=$vrfPubKey"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }
  }

  def doRegisterForger(invocation: Invocation, gasView: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {

    log.info(s"register forger called")

    val stakedAmount = invocation.value

    // check that msg.value is greater than zero
    if (stakedAmount.signum() <= 0) {
      throw new ExecutionRevertedException("Value must not be zero")
    }

    // check that msg.value is a legal wei amount convertible to satoshis without any remainder and that
    // it is over the minimum threshold
    if (!isValidZenAmount(stakedAmount)) {
      val errMsg = s"Value is not a legal wei amount: ${stakedAmount.toString()}"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }
    if (stakedAmount.compareTo(MIN_REGISTER_FORGER_STAKED_AMOUNT_IN_WEI) < 0) {
      val errMsg = s"Value ${stakedAmount.toString()} is below the minimum stake amount threshold: ${MIN_REGISTER_FORGER_STAKED_AMOUNT_IN_WEI} "
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }

    val delegatorAddress = invocation.caller

    // check that sender account exists
    if (!gasView.accountExists(delegatorAddress)) {

      val errMsg = s"Sender account does not exist: msg = ${context.msg}"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }

    val inputParams = getArgumentsFromData(invocation.input)

    val cmdInput = RegisterForgerCmdInputDecoder.decode(inputParams)
    val blockSignPubKey = cmdInput.forgerPublicKeys.blockSignPublicKey
    val vrfPubKey = cmdInput.forgerPublicKeys.vrfPublicKey
    val rewardShare = cmdInput.rewardShare
    val smartContractAddr = cmdInput.smartContractAddress
    val sign25519 = cmdInput.signature25519
    val signVrf = cmdInput.signatureVrf

    // check that rewardShare is in legal range
    if (rewardShare < 0 || rewardShare > 1000) {
      val errMsg = s"Illegal reward share value: = ${rewardShare}"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }

    // we take for granted that forger list is open TODO comment also in fork list

    // check we do not have this forger yet. This is an early check, addForger will do it as well
    if (getForger(gasView, blockSignPubKey, vrfPubKey).isDefined) {
      val errMsg = s"Can not register an already existing forger: ${ForgerPublicKeys(blockSignPubKey, vrfPubKey).toString}"
      log.warn(errMsg)
      throw new ExecutionRevertedException(errMsg)
    }

    val messageToSign = getHashedMessageToSign(
      BytesUtils.toHexString(blockSignPubKey.pubKeyBytes()),
      BytesUtils.toHexString(vrfPubKey.pubKeyBytes()),
      rewardShare,
      BytesUtils.toHexString(smartContractAddr.toBytes))

    // verify the signatures (trows exceptions)
    verifySignatures(messageToSign, blockSignPubKey, vrfPubKey, sign25519, signVrf)

    // add new forger to the db
    addForger(gasView, blockSignPubKey, vrfPubKey, rewardShare, smartContractAddr,
      context.blockContext.consensusEpochNumber, delegatorAddress, stakedAmount)

    log.info(s"register forger exiting - ${cmdInput.toString}")
    Array.emptyByteArray
  }

  def doDelegateCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = DelegateCmdInputDecoder.decode(inputParams)
    log.info(s"delegate called - ${cmdInput.forgerPublicKeys}")
    //TODO: add logic
    Array.emptyByteArray
  }

  def doWithdrawCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = WithdrawCmdInputDecoder.decode(inputParams)
    log.info(s"withdraw called - ${cmdInput.forgerPublicKeys} ${cmdInput.value}")

    //TODO: add logic
    Array.emptyByteArray
  }

  def doStakeTotalCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = StakeTotalCmdInputDecoder.decode(inputParams)
    log.info(s"stakeTotal called - ${cmdInput.forgerPublicKeys} ${cmdInput.delegator} epochStart: ${cmdInput.consensusEpochStart} - maxNumOfEpoch: ${cmdInput.maxNumOfEpoch}")

    //TODO: add logic and return data

    Array.emptyByteArray
  }

  def doPagedForgersStakesByDelegatorCmd(invocation: Invocation, view: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = PagedForgersStakesByDelegatorCmdInputDecoder.decode(inputParams)
    log.debug(s"getPagedForgersStakesByDelegator called - ${cmdInput.delegator} startIndex: ${cmdInput.startIndex} - pageSize: ${cmdInput.pageSize}")

    val result = getPagedForgersStakesByDelegator(view, cmdInput.delegator, cmdInput.startIndex, cmdInput.pageSize)
    PagedForgersStakesByDelegatorOutput(result.nextStartPos, result.stakesData).encode()
  }

  def doPagedForgersStakesByForgerCmd(invocation: Invocation, view: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = PagedForgersStakesByForgerCmdInputDecoder.decode(inputParams)
    log.debug(s"getPagedForgersStakesByForger called - ${cmdInput.forgerPublicKeys} startIndex: ${cmdInput.startIndex} - pageSize: ${cmdInput.pageSize}")

    val response = getPagedForgersStakesByForger(view, cmdInput.forgerPublicKeys, cmdInput.startIndex, cmdInput.pageSize)
    PagedForgersStakesByForgerOutput(response.nextStartPos, response.stakesData).encode()
  }


  override def getPagedForgersStakesByForger(view: BaseAccountStateView, forger: ForgerPublicKeys, startPos: Int, pageSize: Int): PagedStakesByForgerResponse = {
    StakeStorage.getPagedForgersStakesByForger(view, forger, startPos, pageSize)
  }

  override def getPagedForgersStakesByDelegator(view: BaseAccountStateView, delegator: Address, startPos: Int, pageSize: Int): PagedStakesByDelegatorResponse = {
    StakeStorage.getPagedForgersStakesByDelegator(view, delegator, startPos, pageSize)
  }


  def doActivateCmd(invocation: Invocation, view: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {

    //Check is well formed
    requireIsNotPayable(invocation)
    checkInputDoesntContainParams(invocation)

    //Check it cannot called twice
    if (StakeStorage.isActive(view)) {
      val msgStr = s"Forger stake V2 already activated"
      log.debug(msgStr)
      throw new ExecutionRevertedException(msgStr)
    }

    val intrinsicGas = invocation.gasPool.getUsedGas

    //Call "disableAndMigrate" on old forger stake msg processor, so it won't be used anymore.
    //It returns all existing stakes that will be recreated in the ForgerStakes V2
    val result = context.execute(invocation.call(FORGER_STAKE_SMART_CONTRACT_ADDRESS, BigInteger.ZERO,
      BytesUtils.fromHexString(ForgerStakeMsgProcessor.DisableAndMigrateCmd), invocation.gasPool.getGas))
    val listOfExistingStakes = AccountForgingStakeInfoListDecoder.decode(result).listOfStakes
    val stakesByForger = listOfExistingStakes.groupBy(_.forgerStakeData.forgerPublicKeys)

    val epochNumber = context.blockContext.consensusEpochNumber

    var totalMigratedStakeAmount = BigInteger.ZERO
    stakesByForger.foreach { case (forgerKeys, stakesByForger) =>
      // Sum the stakes by delegator
      val stakesByDelegator = stakesByForger.groupBy(_.forgerStakeData.ownerPublicKey)
      val listOfTotalStakesByDelegator = stakesByDelegator.mapValues(_.foldLeft(BigInteger.ZERO) {
        (sum, stake) => sum.add(stake.forgerStakeData.stakedAmount)
      })
      //Take first delegator for registering the forger
      val (firstDelegator, firstDelegatorStakeAmount) = listOfTotalStakesByDelegator.head
      //in this case we don't have to check the 10 ZEN minimum threshold for adding a new forger
      StakeStorage.addForger(view, forgerKeys.blockSignPublicKey,
        forgerKeys.vrfPublicKey, 0, Address.ZERO, epochNumber, firstDelegator.address(), firstDelegatorStakeAmount)
      totalMigratedStakeAmount = totalMigratedStakeAmount.add(firstDelegatorStakeAmount)
      listOfTotalStakesByDelegator.tail.foreach { case (delegator, delegatorStakeAmount) =>
        StakeStorage.addStake(view, forgerKeys.blockSignPublicKey, forgerKeys.vrfPublicKey,
          epochNumber, delegator.address(), delegatorStakeAmount)
        totalMigratedStakeAmount = totalMigratedStakeAmount.add(delegatorStakeAmount)
      }
    }

    //Update the balance of both forger stake msg processors
    view.subBalance(FORGER_STAKE_SMART_CONTRACT_ADDRESS, totalMigratedStakeAmount)
    view.addBalance(FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS, totalMigratedStakeAmount)

    // Refund the used gas, because activate should be free, except for the intrinsic gas
    invocation.gasPool.addGas(invocation.gasPool.getUsedGas.subtract(intrinsicGas))

    StakeStorage.setActive(view)

    val activateEvent = ActivateStakeV2()
    val evmLog = getEthereumConsensusDataLog(activateEvent)
    view.addLog(evmLog)

    log.info(s"Forger stakes V2 activated successfully - ${listOfExistingStakes.size} items migrated, " +
      s"total stake amount $totalMigratedStakeAmount")
    Array.emptyByteArray
  }


  val RegisterForgerCmd: String = getABIMethodId("registerForger(bytes32,bytes32,bytes1,uint32,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes1)")
  val DelegateCmd: String = getABIMethodId("delegate(bytes32,bytes32,bytes1)")
  val WithdrawCmd: String = getABIMethodId("withdraw(bytes32,bytes32,bytes1,uint256)")
  val StakeTotalCmd: String = getABIMethodId("stakeTotal(bytes32,bytes32,bytes1,address,uint32,uint32)")
  val GetPagedForgersStakesByForgerCmd: String = getABIMethodId("getPagedForgersStakesByForger(bytes32,bytes32,bytes1,int32,int32)");
  val GetPagedForgersStakesByDelegatorCmd: String = getABIMethodId("getPagedForgersStakesByDelegator(address,int32,int32)");
  val ActivateCmd: String = getABIMethodId("activate()");

  // ensure we have strings consistent with size of opcode
  require(
    RegisterForgerCmd.length == 2 * METHOD_ID_LENGTH &&
    DelegateCmd.length == 2 * METHOD_ID_LENGTH &&
    WithdrawCmd.length == 2 * METHOD_ID_LENGTH &&
    StakeTotalCmd.length == 2 * METHOD_ID_LENGTH &&
    ActivateCmd.length == 2 * METHOD_ID_LENGTH &&
    GetPagedForgersStakesByForgerCmd.length == 2 * METHOD_ID_LENGTH &&
    GetPagedForgersStakesByDelegatorCmd.length == 2 * METHOD_ID_LENGTH
  )
}
