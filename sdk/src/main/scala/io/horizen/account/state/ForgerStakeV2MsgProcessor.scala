package io.horizen.account.state

import io.horizen.account.abi.ABIUtil.{METHOD_ID_LENGTH, getABIMethodId, getArgumentsFromData, getFunctionSignature}
import io.horizen.account.fork.Version1_4_0Fork
import io.horizen.account.state.events.ActivateStakeV2
import io.horizen.account.state.nativescdata.forgerstakev2._
import io.horizen.account.utils.WellKnownAddresses.{FORGER_STAKE_SMART_CONTRACT_ADDRESS, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS}
import io.horizen.consensus.ForgingStakeInfo
import io.horizen.evm.Address
import io.horizen.utils.BytesUtils
import sparkz.crypto.hash.Keccak256
import java.math.BigInteger

trait ForgerStakesV2Provider {
  private[horizen] def getPagedForgersStakesByForger(view: BaseAccountStateView, forger: ForgerPublicKeys, startPos: Int, pageSize: Int): PagedStakesByForgerResponse
  private[horizen] def getPagedForgersStakesByDelegator(view: BaseAccountStateView, delegator: Address, startPos: Int, pageSize: Int): PagedStakesByDelegatorResponse
}

object ForgerStakeV2MsgProcessor extends NativeSmartContractWithFork  with ForgerStakesV2Provider {
  override val contractAddress: Address = FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
  override val contractCode: Array[Byte] = Keccak256.hash("ForgerStakeV2SmartContractCode")

  override def isForkActive(consensusEpochNumber: Int): Boolean = {
    Version1_4_0Fork.get(consensusEpochNumber).active
  }

  override def process(invocation: Invocation, view: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {
    if (!Version1_4_0Fork.get(context.blockContext.consensusEpochNumber).active)
      throw new ExecutionRevertedException(s"fork not active")
    val gasView = view.getGasTrackedView(invocation.gasPool)
    getFunctionSignature(invocation.input) match {
      case DelegateCmd =>
        doDelegateCmd(invocation, gasView, context.msg)
      case WithdrawCmd =>
        doWithdrawCmd(invocation, gasView, context.msg)
      case StakeTotalCmd =>
        doStakeTotalCmd(invocation, gasView, context.blockContext.consensusEpochNumber)
      case GetPagedForgersStakesByForgerCmd =>
        doPagedForgersStakesByForgerCmd(invocation, gasView, context.msg)
      case GetPagedForgersStakesByDelegatorCmd =>
        doPagedForgersStakesByDelegatorCmd(invocation, gasView, context.msg)
      case ActivateCmd =>
        doActivateCmd(invocation, view, context) // That shouldn't consume gas, so it doesn't use gasView
      case opCodeHex => throw new ExecutionRevertedException(s"op code not supported: $opCodeHex")
    }
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

  def doStakeTotalCmd(invocation: Invocation, view: BaseAccountStateView, currentEpoch: Int): Array[Byte] = {
    requireIsNotPayable(invocation)
    if (!StakeStorage.isActive(view)) {
      val msgStr = s"Forger stake V2 is not activated"
      throw new ExecutionRevertedException(msgStr)
    }

    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = StakeTotalCmdInputDecoder.decode(inputParams)

    val forgerKeys = cmdInput.forgerPublicKeys
    val delegator = cmdInput.delegator
    val consensusEpochStart = if (cmdInput.consensusEpochStart.isEmpty) currentEpoch else cmdInput.consensusEpochStart.get
    val maxNumOfEpoch = cmdInput.maxNumOfEpoch
    log.info(s"stakeTotal called - $forgerKeys $delegator epochStart: $consensusEpochStart - maxNumOfEpoch: $maxNumOfEpoch")

    if (forgerKeys.isEmpty && delegator.isDefined) {
      val msgStr = s"Illegal argument - delegator is defined while forger keys are not"
      throw new ExecutionRevertedException(msgStr)
    }
    val consensusEpochEnd =
      if (maxNumOfEpoch.isEmpty) consensusEpochStart
      else if (consensusEpochStart + maxNumOfEpoch.get > currentEpoch) currentEpoch
      else consensusEpochStart + maxNumOfEpoch.get - 1

    val response: StakeTotalCmdOutput = StakeStorage.getStakeTotal(view, forgerKeys, delegator, consensusEpochStart, consensusEpochEnd)

    response.encode()
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
      val listOfTotalStakesByDelegator = stakesByDelegator.mapValues(_.foldLeft(BigInteger.ZERO){
        (sum, stake) => sum.add(stake.forgerStakeData.stakedAmount)})
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


  val DelegateCmd: String = getABIMethodId("delegate(bytes32,bytes32,bytes1)")
  val WithdrawCmd: String = getABIMethodId("withdraw(bytes32,bytes32,bytes1,uint256)")
  val StakeTotalCmd: String = getABIMethodId("stakeTotal(bytes32,bytes32,bytes1,address,uint32,uint32)")
  val GetPagedForgersStakesByForgerCmd: String = getABIMethodId("getPagedForgersStakesByForger(bytes32,bytes32,bytes1,int32,int32)");
  val GetPagedForgersStakesByDelegatorCmd: String = getABIMethodId("getPagedForgersStakesByDelegator(address,int32,int32)");
  val ActivateCmd: String = getABIMethodId("activate()");

  // ensure we have strings consistent with size of opcode
  require(
    DelegateCmd.length == 2 * METHOD_ID_LENGTH &&
    WithdrawCmd.length == 2 * METHOD_ID_LENGTH &&
    StakeTotalCmd.length == 2 * METHOD_ID_LENGTH &&
    ActivateCmd.length == 2 * METHOD_ID_LENGTH &&
    GetPagedForgersStakesByForgerCmd.length == 2 * METHOD_ID_LENGTH &&
    GetPagedForgersStakesByDelegatorCmd.length == 2 * METHOD_ID_LENGTH
  )

  override private[horizen] def getPagedListOfForgersStakes(view: BaseAccountStateView, startPos: Int, pageSize: Int) = {
    StakeStorage.getPagedListOfForgers(view, startPos, pageSize)
  }

  override private[horizen] def getListOfForgersStakes(view: BaseAccountStateView) = {
    StakeStorage.getAllForgerStakes(view)
  }

  override private[horizen] def getForgingStakes(view: BaseAccountStateView): Seq[ForgingStakeInfo] = {
    StakeStorage.getForgingStakes(view)
  }

  override private[horizen] def isActive(view: BaseAccountStateView): Boolean = StakeStorage.isActive(view)
}
