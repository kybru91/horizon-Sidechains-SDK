package io.horizen.account.state

import io.horizen.account.abi.ABIUtil.{METHOD_ID_LENGTH, getABIMethodId, getArgumentsFromData, getFunctionSignature}
import io.horizen.account.fork.Version1_4_0Fork
import io.horizen.account.state.nativescdata.forgerstakev2._
import io.horizen.account.state.nativescdata.forgerstakev2.events.{ActivateStakeV2, DelegateForgerStake, WithdrawForgerStake}
import io.horizen.account.utils.WellKnownAddresses.{FORGER_STAKE_SMART_CONTRACT_ADDRESS, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS}
import io.horizen.account.utils.ZenWeiConverter.isValidZenAmount
import io.horizen.evm.Address
import io.horizen.utils.BytesUtils
import sparkz.crypto.hash.Keccak256

import java.math.BigInteger

object ForgerStakeV2MsgProcessor extends NativeSmartContractWithFork {
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
        doDelegateCmd(invocation, gasView, context)
      case WithdrawCmd =>
        doWithdrawCmd(invocation, gasView, context)
      case StakeTotalCmd  =>
        doStakeTotalCmd(invocation, gasView, context.msg)
      case GetPagedForgersStakesByForgerCmd  =>
        doPagedForgersStakesByForgerCmd(invocation, gasView, context.msg)
      case GetPagedForgersStakesByDelegatorCmd  =>
        doPagedForgersStakesByDelegatorCmd(invocation, gasView, context.msg)
      case ActivateCmd  =>
        doActivateCmd(invocation, view, context) // That shouldn't consume gas, so it doesn't use gasView
      case opCodeHex => throw new ExecutionRevertedException(s"op code not supported: $opCodeHex")
    }
  }

  def doDelegateCmd(invocation: Invocation, view: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {

    checkForgerStakesV2IsActive(view)

    val inputParams = getArgumentsFromData(invocation.input)
    val DelegateCmdInput(forgerPublicKeys) = DelegateCmdInputDecoder.decode(inputParams)

    log.info(s"delegate called - $forgerPublicKeys")
    val stakedAmount = invocation.value

    if (stakedAmount.signum() <= 0) {
      throw new ExecutionRevertedException("Value must not be zero")
    }

    if (!isValidZenAmount(stakedAmount)) {
      throw new ExecutionRevertedException(s"Value is not a legal wei amount: $stakedAmount")
    }

    if (view.getBalance(invocation.caller).compareTo(stakedAmount) < 0){
      throw new ExecutionRevertedException(s"Insufficient funds. Required: $stakedAmount, available: ${view.getBalance(invocation.caller)}")
    }

    val epochNumber = context.blockContext.consensusEpochNumber

    StakeStorage.addStake(view, forgerPublicKeys.blockSignPublicKey, forgerPublicKeys.vrfPublicKey,
      epochNumber, invocation.caller, stakedAmount)

    val delegateStakeEvt = DelegateForgerStake(invocation.caller, forgerPublicKeys.blockSignPublicKey, forgerPublicKeys.vrfPublicKey, stakedAmount)
    val evmLog = getEthereumConsensusDataLog(delegateStakeEvt)
    view.addLog(evmLog)

    view.subBalance(invocation.caller, stakedAmount)
    // increase the balance of the "forger stake smart contract” account
    view.addBalance(contractAddress, stakedAmount)


    Array.emptyByteArray
  }

  def doWithdrawCmd(invocation: Invocation, view: BaseAccountStateView, context: ExecutionContext): Array[Byte] = {
    requireIsNotPayable(invocation)
    checkForgerStakesV2IsActive(view)

    val inputParams = getArgumentsFromData(invocation.input)
    val WithdrawCmdInput(forgerPublicKeys, stakedAmount) = WithdrawCmdInputDecoder.decode(inputParams)

    if (stakedAmount.signum() != 1) throw new ExecutionRevertedException(s"Withdrawal amount must be greater than zero: $stakedAmount")

    if (!isValidZenAmount(stakedAmount)) {
      throw new ExecutionRevertedException(s"Value is not a legal wei amount: $stakedAmount")
    }

    log.debug(s"withdraw called - $forgerPublicKeys $stakedAmount")

    val epochNumber = context.blockContext.consensusEpochNumber

    StakeStorage.removeStake(view, forgerPublicKeys.blockSignPublicKey, forgerPublicKeys.vrfPublicKey,
      epochNumber, invocation.caller, stakedAmount)

    val withdrawStakeEvt = WithdrawForgerStake(invocation.caller, forgerPublicKeys.blockSignPublicKey, forgerPublicKeys.vrfPublicKey, stakedAmount)
    val evmLog = getEthereumConsensusDataLog(withdrawStakeEvt)
    view.addLog(evmLog)

    view.subBalance(contractAddress, stakedAmount)
    view.addBalance(invocation.caller, stakedAmount)

    Array.emptyByteArray
  }

  private def checkForgerStakesV2IsActive(view: BaseAccountStateView): Unit = {
    if (!StakeStorage.isActive(view)) {
      throw new ExecutionRevertedException("Forger stake V2 has not been activated yet")
    }
  }

  def doStakeTotalCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = StakeTotalCmdInputDecoder.decode(inputParams)
    log.info(s"stakeTotal called - ${cmdInput.forgerPublicKeys} ${cmdInput.delegator} epochStart: ${cmdInput.consensusEpochStart} - maxNumOfEpoch: ${cmdInput.maxNumOfEpoch}")

    //TODO: add logic and return data

    Array.emptyByteArray
  }

  def doPagedForgersStakesByDelegatorCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = PagedForgersStakesByDelegatorCmdInputDecoder.decode(inputParams)
    log.info(s"getPagedForgersStakesByDelegator called - ${cmdInput.delegator} startIndex: ${cmdInput.startIndex} - pageSize: ${cmdInput.pageSize}")

    //TODO: add logic and return data

    Array.emptyByteArray
  }

  def doPagedForgersStakesByForgerCmd(invocation: Invocation, gasView: BaseAccountStateView, msg: Message): Array[Byte] = {
    val inputParams = getArgumentsFromData(invocation.input)
    val cmdInput = PagedForgersStakesByForgerCmdInputDecoder.decode(inputParams)
    log.info(s"getPagedForgersStakesByForger called - ${cmdInput.forgerPublicKeys} startIndex: ${cmdInput.startIndex} - pageSize: ${cmdInput.pageSize}")

    //TODO: add logic and return data

    Array.emptyByteArray
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

    //Get all existing stakes from old native contract
    val result = context.execute(invocation.call(FORGER_STAKE_SMART_CONTRACT_ADDRESS, BigInteger.ZERO,
      BytesUtils.fromHexString(ForgerStakeMsgProcessor.GetListOfForgersCmd), invocation.gasPool.getGas))
    val listOfExistingStakes = AccountForgingStakeInfoListDecoder.decode(result).listOfStakes
    val stakesByForger = listOfExistingStakes.groupBy(_.forgerStakeData.forgerPublicKeys)

    val epochNumber = context.blockContext.consensusEpochNumber

    stakesByForger.foreach { case (forgerKeys, stakesByForger) =>
      // Sum the stakes by delegator
      val stakesByDelegator = stakesByForger.groupBy(_.forgerStakeData.ownerPublicKey)
      val listOfTotalStakesByDelegator = stakesByDelegator.mapValues(_.foldLeft(BigInteger.ZERO){
        (sum, stake) => sum.add(stake.forgerStakeData.stakedAmount)})
      //Take first delegator for registering the forger
      val (firstDelegator, firstDelegatorStakeAmount) = listOfTotalStakesByDelegator.head
      StakeStorage.addForger(view, forgerKeys.blockSignPublicKey,
        forgerKeys.vrfPublicKey, 0, Address.ZERO, epochNumber, firstDelegator.address(), firstDelegatorStakeAmount)
      listOfTotalStakesByDelegator.tail.foreach { case (delegator, delegatorStakeAmount) =>
        StakeStorage.addStake(view, forgerKeys.blockSignPublicKey, forgerKeys.vrfPublicKey,
          epochNumber, delegator.address(), delegatorStakeAmount)
      }
    }

    //Call "disable" on old forger stake msg processor, so it won't be used anymore
    context.execute(invocation.call(FORGER_STAKE_SMART_CONTRACT_ADDRESS, BigInteger.ZERO,
      BytesUtils.fromHexString(ForgerStakeMsgProcessor.DisableCmd), invocation.gasPool.getGas))

    // Refund the used gas, because activate should be free, except for the intrinsic gas
    invocation.gasPool.addGas(invocation.gasPool.getUsedGas.subtract(intrinsicGas))

    val activateEvent = ActivateStakeV2()
    val evmLog = getEthereumConsensusDataLog(activateEvent)
    view.addLog(evmLog)

    StakeStorage.setActive(view)

    log.info(s"Forger stakes V2 activated successfully - ${listOfExistingStakes.size} items migrated")
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
}
