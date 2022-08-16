package com.horizen.account.state

import com.google.common.primitives.Bytes
import com.horizen.SidechainTypes
import com.horizen.account.proposition.AddressProposition
import com.horizen.account.receipt.EthereumConsensusDataReceipt.ReceiptStatus
import com.horizen.account.receipt.{EthereumConsensusDataReceipt, EthereumReceipt}
import com.horizen.account.state.ForgerStakeMsgProcessor.{AddNewStakeCmd, ForgerStakeSmartContractAddress}
import com.horizen.account.storage.AccountStateMetadataStorageView
import com.horizen.account.transaction.EthereumTransaction
import com.horizen.account.utils.{MainchainTxCrosschainOutputAddressUtil, ZenWeiConverter}
import com.horizen.block.{MainchainBlockReferenceData, MainchainTxForwardTransferCrosschainOutput, MainchainTxSidechainCreationCrosschainOutput, WithdrawalEpochCertificate}
import com.horizen.consensus.{ConsensusEpochNumber, ForgingStakeInfo}
import com.horizen.evm.interop.EvmLog
import com.horizen.evm.{ResourceHandle, StateDB, StateStorageStrategy}
import com.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import com.horizen.state.StateView
import com.horizen.transaction.exception.TransactionSemanticValidityException
import com.horizen.transaction.mainchain.{ForwardTransfer, SidechainCreation}
import com.horizen.utils.{BlockFeeInfo, BytesUtils, WithdrawalEpochInfo}
import scorex.core.VersionTag
import scorex.util.ScorexLogging

import java.math.BigInteger
import scala.collection.JavaConverters.collectionAsScalaIterableConverter
import scala.util.Try

class AccountStateView(metadataStorageView: AccountStateMetadataStorageView,
                       stateDb: StateDB,
                       messageProcessors: Seq[MessageProcessor])
  extends StateView[SidechainTypes#SCAT]
    with BaseAccountStateView
    with AutoCloseable
    with ScorexLogging {

  lazy val withdrawalReqProvider: WithdrawalRequestProvider = messageProcessors.find(_.isInstanceOf[WithdrawalRequestProvider]).get.asInstanceOf[WithdrawalRequestProvider]
  lazy val forgerStakesProvider: ForgerStakesProvider = messageProcessors.find(_.isInstanceOf[ForgerStakesProvider]).get.asInstanceOf[ForgerStakesProvider]

  // modifiers
  override def applyMainchainBlockReferenceData(refData: MainchainBlockReferenceData): Try[Unit] = Try {
    refData.sidechainRelatedAggregatedTransaction.foreach(aggTx => {
      aggTx.mc2scTransactionsOutputs().asScala.map {
        case sc: SidechainCreation =>
          // While processing sidechain creation output:
          // 1. extract first forger stake info: block sign public key, vrf public key, owner address, stake amount
          // 2. store the stake info record in the forging fake smart contract storage
          val scOut: MainchainTxSidechainCreationCrosschainOutput = sc.getScCrOutput

          val stakedAmount = ZenWeiConverter.convertZenniesToWei(scOut.amount)

          val ownerAddressProposition = new AddressProposition(
            MainchainTxCrosschainOutputAddressUtil.getAccountAddress(scOut.address))

          // customData = vrf key | blockSignerKey
          val vrfPublicKey = new VrfPublicKey(scOut.customCreationData.take(VrfPublicKey.KEY_LENGTH))
          val blockSignerProposition = new PublicKey25519Proposition(scOut.customCreationData.slice(VrfPublicKey.KEY_LENGTH, VrfPublicKey.KEY_LENGTH + PublicKey25519Proposition.KEY_LENGTH))

          val cmdInput = AddNewStakeCmdInput(
            ForgerPublicKeys(blockSignerProposition, vrfPublicKey),
            ownerAddressProposition
          )
          val data = Bytes.concat(BytesUtils.fromHexString(AddNewStakeCmd), cmdInput.encode())

          val message = new Message(
            ownerAddressProposition,
            ForgerStakeSmartContractAddress,
            BigInteger.ZERO, // gasPrice
            BigInteger.ZERO, // gasFeeCap
            BigInteger.ZERO, // gasTipCap
            BigInteger.ZERO, // gasLimit
            stakedAmount,
            BigInteger.ONE.negate(), // a negative nonce value will rule out collision with real transactions
            data)

          val returnData = forgerStakesProvider.addScCreationForgerStake(message, this)
          log.debug(s"sc creation forging stake added with stakeid: ${BytesUtils.toHexString(returnData)}")

        case ft: ForwardTransfer =>
          val ftOut: MainchainTxForwardTransferCrosschainOutput = ft.getFtOutput

          // we trust the MC that this is a valid amount
          val value = ZenWeiConverter.convertZenniesToWei(ftOut.amount)

          val recipientProposition = new AddressProposition(
            MainchainTxCrosschainOutputAddressUtil.getAccountAddress(ftOut.propositionBytes))

          // stateDb will implicitly create account if not existing yet
          addBalance(recipientProposition.address(), value)
          log.debug(s"added FT amount = $value to address=$recipientProposition")
      }
    })
  }

  override def getListOfForgerStakes: Seq[AccountForgingStakeInfo] =
    forgerStakesProvider.getListOfForgers(this)

  override def getForgerStakeData(stakeId: String): Option[ForgerStakeData] =
    forgerStakesProvider.findStakeData(this, BytesUtils.fromHexString(stakeId))

  def getOrderedForgingStakeInfoSeq: Seq[ForgingStakeInfo] = {
    forgerStakesProvider.getListOfForgers(this).map { item =>
      ForgingStakeInfo(
        item.forgerStakeData.forgerPublicKeys.blockSignPublicKey,
        item.forgerStakeData.forgerPublicKeys.vrfPublicKey,
        ZenWeiConverter.convertWeiToZennies(item.forgerStakeData.stakedAmount))
    }.sorted(Ordering[ForgingStakeInfo].reverse)
  }

  def setupTxContext(txHash: Array[Byte], idx: Integer): Unit = {
    // set context for the created events/logs assignment
    stateDb.setTxContext(txHash, idx)
  }

  private def preCheck(msg: Message): Unit = {
    // We are sure that transaction is semantically valid (so all the tx fields are valid)
    // and was successfully verified by ChainIdBlockSemanticValidator

    // call these only once as they are not a simple getters
    val sender = msg.getFrom

    // Check the nonce
    val stateNonce = getNonce(sender.address())
    val txNonce = msg.getNonce
    val result = txNonce.compareTo(stateNonce)
    if (result < 0) {
      throw new TransactionSemanticValidityException(
        s"nonce too low: address ${sender.checksumAddress()}, tx: $txNonce, state: $stateNonce")
    } else if (result > 0) {
      throw new TransactionSemanticValidityException(
        s"nonce too high: address ${sender.checksumAddress()}, tx: $txNonce, state: $stateNonce")
    }
    // GETH and therefore StateDB use uint64 to store the nonce and perform an overflow check here using (nonce+1<nonce)
    // BigInteger will not overflow like that, so we just verify that the result after increment still fits into 64 bits
    if (stateNonce.add(BigInteger.ONE).bitLength() > 64)
      throw new TransactionSemanticValidityException(
        s"nonce has max value: address ${sender.checksumAddress()}, nonce: $stateNonce")

    // Check that the sender is an EOA
    if (!isEoaAccount(sender.address())) {
      val codeHash = BytesUtils.toHexString(getCodeHash(sender.address()))
      throw new TransactionSemanticValidityException(
        s"sender not an eoa: address ${sender.checksumAddress()}, codeHash: $codeHash")
    }

    if (msg.getGasFeeCap.compareTo(getBaseFee) < 0)
      throw new TransactionSemanticValidityException(
        s"max fee per gas less than block base fee: address ${sender.checksumAddress()}, maxFeePerGas: ${msg.getGasFeeCap}, baseFee: $getBaseFee")
  }

  private def buyGas(msg: Message, blockGasPool: GasPool): GasPool = {
    val gas = msg.getGasLimit
    // with a legacy TX gasPrice will be the one set by the caller
    // with an EIP1559 TX gasPrice will be the effective gasPrice (baseFee+tip, capped at feeCap)
    val effectiveFees = gas.multiply(msg.getGasPrice)
    // maxFees is calculated using the feeCap, even if the cap was not reached, i.e. baseFee+tip < feeCap
    val maxFees = if (msg.getGasFeeCap == null) effectiveFees else gas.multiply(msg.getGasFeeCap)
    // make sure the sender has enough balance to cover max fees plus value
    val sender = msg.getFrom
    val have = getBalance(sender.address())
    val want = maxFees.add(msg.getValue)
    if (have.compareTo(want) < 0) {
      throw new TransactionSemanticValidityException(s"insufficient funds for gas * price + value: address ${sender.checksumAddress()} have $have want $want")
    }
    // deduct gas from gasPool of the current block (unused gas will be returned after execution)
    blockGasPool.consumeGas(gas)
    // prepay effective gas fees
    subBalance(sender.address(), effectiveFees)
    // allocate gas for this transaction
    new GasPool(gas)
  }

  private def refundGas(msg: Message, txGasPool: GasPool, blockGasPool: GasPool): Unit = {
    val quotient = 5 // pre-EIP-3529 this was 2 (london release)
    val max = txGasPool.getUsedGas.divide(BigInteger.valueOf(quotient))
    val refund = stateDb.getRefund match {
      // cap refund to a quotient of the used gas
      case refund if refund.compareTo(max) > 1 => max
      case refund => refund
    }
    txGasPool.returnGas(refund)
    // return funds for remaining gas, exchanged at the original rate.
    val remaining = txGasPool.getAvailableGas.multiply(msg.getGasPrice)
    addBalance(msg.getFrom.address(), remaining)

    // return remaining gas to the gasPool of the current block so it is available for the next transaction
    blockGasPool.returnGas(txGasPool.getAvailableGas)
  }

  def applyMessage(msg: Message, blockGasPool: GasPool): Array[Byte] = {
    val txGasPool = try {
      buyGas(msg, blockGasPool)
    } catch {
      // throw an Exception that is not ExecutionFailedException
      case err: OutOfGasException => throw new Exception("block gas limit reached", err);
    }
    try {
      // always consume intrinsic gas
      txGasPool.consumeGas(GasCalculator.intrinsicGas(msg.getData, msg.getTo == null))
    } catch {
      // throw an Exception that is not ExecutionFailedException
      case err: OutOfGasException => throw new Exception("intrinsic gas too low", err);
    }

    messageProcessors.find(_.canProcess(msg, this)) match {
      case None => throw new IllegalArgumentException("Unable to process message.")
      case Some(processor) =>
        val revisionId = stateDb.snapshot()
        try {
          processor.process(msg, this)
        } catch {
          // if the processor throws ExecutionFailedException we revert all changes and consume any remaining gas
          // any other exception will bubble up and invalidate the block
          case err: ExecutionFailedException =>
            stateDb.revertToSnapshot(revisionId)
            txGasPool.consumeGas(txGasPool.getAvailableGas)
            throw err
        } finally {
          refundGas(msg, txGasPool, blockGasPool)
        }
    }
  }

  /**
   * Possible outcomes:
   *  - tx applied succesfully => Receipt with status success
   *  - tx execution failed => Receipt with status failed
   *    - if any ExecutionFailedException was thrown, including but not limited to:
   *    - OutOfGasException (not intrinsic gas, see below!)
   *    - EvmException (EVM reverted) / fake contract exception
   *  - tx could not be applied => throws an exception (this will lead to and invalid block)
   *    - any of the preChecks fail
   *    - not enough gas for intrinsic gas
   *    - block gas limit reached
   */
  override def applyTransaction(tx: SidechainTypes#SCAT, txIndex: Int, blockGasPool: GasPool): Try[EthereumConsensusDataReceipt] = Try {
    if (!tx.isInstanceOf[EthereumTransaction])
      throw new IllegalArgumentException(s"Unsupported transaction type ${tx.getClass.getName}")

    val ethTx = tx.asInstanceOf[EthereumTransaction]
    val txHash = BytesUtils.fromHexString(ethTx.id)
    val msg = ethTx.asMessage(getBaseFee)

    // Tx context for stateDB, to know where to keep EvmLogs
    setupTxContext(txHash, txIndex)

    // do preliminary checks
    preCheck(msg)

    // increase the nonce by 1
    increaseNonce(msg.getFrom.address())

    // apply message to state
    val status = try {
      applyMessage(msg, blockGasPool)
      ReceiptStatus.SUCCESSFUL
    } catch {
      // any other exception will bubble up and invalidate the block
      case err: ExecutionFailedException =>
        log.error("applying message failed", err)
        ReceiptStatus.FAILED
    }
    val consensusDataReceipt = new EthereumConsensusDataReceipt(
      ethTx.version(), status.id, blockGasPool.getUsedGas, getLogs(txHash))
    log.debug(s"Returning consensus data receipt: ${consensusDataReceipt.toString()}")
    consensusDataReceipt
  }

  override def isEoaAccount(address: Array[Byte]): Boolean = stateDb.isEoaAccount(address)

  override def isSmartContractAccount(address: Array[Byte]): Boolean = stateDb.isSmartContractAccount(address)

  override def accountExists(address: Array[Byte]): Boolean = !stateDb.isEmpty(address)

  // account modifiers:
  override def addAccount(address: Array[Byte], codeHash: Array[Byte]): Unit =
    stateDb.setCodeHash(address, codeHash)

  override def addBalance(address: Array[Byte], amount: BigInteger): Unit =
    stateDb.addBalance(address, amount)

  override def subBalance(address: Array[Byte], amount: BigInteger): Unit = {
    // stateDb lib does not do any sanity check, and negative balances might arise (and java/go json IF does not correctly handle it)
    // TODO: for the time being do the checks here, later they will be done in the caller stack
    require(amount.compareTo(BigInteger.ZERO) >= 0)
    if (amount.compareTo(BigInteger.ZERO) > 0) {
      require(stateDb.getBalance(address).compareTo(amount) >= 0)
    }
    stateDb.subBalance(address, amount)
  }

  override def increaseNonce(address: Array[Byte]): Unit =
    stateDb.setNonce(address, getNonce(address).add(BigInteger.ONE))

  override def updateAccountStorage(address: Array[Byte], key: Array[Byte], value: Array[Byte]): Unit =
    stateDb.setStorage(address, key, value, StateStorageStrategy.RAW)

  override def updateAccountStorageBytes(address: Array[Byte], key: Array[Byte], value: Array[Byte]): Unit =
    stateDb.setStorage(address, key, value, StateStorageStrategy.CHUNKED)

  override def getAccountStorage(address: Array[Byte], key: Array[Byte]): Array[Byte] =
    stateDb.getStorage(address, key, StateStorageStrategy.RAW)

  override def getAccountStorageBytes(address: Array[Byte], key: Array[Byte]): Array[Byte] =
    stateDb.getStorage(address, key, StateStorageStrategy.CHUNKED)

  override def removeAccountStorage(address: Array[Byte], key: Array[Byte]): Unit =
    stateDb.removeStorage(address, key, StateStorageStrategy.RAW)

  override def removeAccountStorageBytes(address: Array[Byte], key: Array[Byte]): Unit =
    stateDb.removeStorage(address, key, StateStorageStrategy.CHUNKED)

  // out-of-the-box helpers
  override def addCertificate(cert: WithdrawalEpochCertificate): Unit =
    metadataStorageView.updateTopQualityCertificate(cert)

  override def addFeeInfo(info: BlockFeeInfo): Unit =
    metadataStorageView.addFeePayment(info)

  override def updateWithdrawalEpochInfo(withdrawalEpochInfo: WithdrawalEpochInfo): Unit =
    metadataStorageView.updateWithdrawalEpochInfo(withdrawalEpochInfo)

  override def updateConsensusEpochNumber(consensusEpochNum: ConsensusEpochNumber): Unit =
    metadataStorageView.updateConsensusEpochNumber(consensusEpochNum)

  override def updateTransactionReceipts(receipts: Seq[EthereumReceipt]): Unit =
    metadataStorageView.updateTransactionReceipts(receipts)

  def getTransactionReceipt(txHash: Array[Byte]): Option[EthereumReceipt] =
    metadataStorageView.getTransactionReceipt(txHash)

  override def setCeased(): Unit = metadataStorageView.setCeased()

  override def commit(version: VersionTag): Try[Unit] = Try {
    // Update StateDB without version, then set the rootHash and commit metadataStorageView
    val rootHash = stateDb.commit()
    metadataStorageView.updateAccountStateRoot(rootHash)
    metadataStorageView.commit(version)
  }

  // getters
  override def withdrawalRequests(withdrawalEpoch: Int): Seq[WithdrawalRequest] =
    withdrawalReqProvider.getListOfWithdrawalReqRecords(withdrawalEpoch, this)

  override def certificate(referencedWithdrawalEpoch: Int): Option[WithdrawalEpochCertificate] =
    metadataStorageView.getTopQualityCertificate(referencedWithdrawalEpoch)

  override def certificateTopQuality(referencedWithdrawalEpoch: Int): Long =
    metadataStorageView.getTopQualityCertificate(referencedWithdrawalEpoch).map(_.quality).getOrElse(0)

  override def getWithdrawalEpochInfo: WithdrawalEpochInfo = metadataStorageView.getWithdrawalEpochInfo

  override def hasCeased: Boolean = metadataStorageView.hasCeased

  override def getConsensusEpochNumber: Option[ConsensusEpochNumber] = metadataStorageView.getConsensusEpochNumber

  override def getFeePayments(withdrawalEpoch: Int): Seq[BlockFeeInfo] =
    metadataStorageView.getFeePayments(withdrawalEpoch)

  override def getAccountStateRoot: Array[Byte] = metadataStorageView.getAccountStateRoot

  override def getHeight: Int = metadataStorageView.getHeight

  // account specific getters
  override def getBalance(address: Array[Byte]): BigInteger = {
    burnGas(BigInteger.ONE)
    stateDb.getBalance(address)
  }

  override def getCodeHash(address: Array[Byte]): Array[Byte] = stateDb.getCodeHash(address)

  override def getNonce(address: Array[Byte]): BigInteger = stateDb.getNonce(address)

  override def getLogs(txHash: Array[Byte]): Array[EvmLog] = stateDb.getLogs(txHash)

  override def addLog(evmLog: EvmLog): Unit = stateDb.addLog(evmLog)

  // when a method is called on a closed handle, LibEvm throws an exception
  override def close(): Unit = stateDb.close()

  override def getStateDbHandle: ResourceHandle = stateDb

  override def getIntermediateRoot: Array[Byte] = stateDb.getIntermediateRoot

  override def getCode(address: Array[Byte]): Array[Byte] = stateDb.getCode(address)

  // TODO: get baseFee for the block
  // TODO: currently a non-zero baseFee makes all the python tests fail, because they do not consider spending fees
  override def getBaseFee: BigInteger = BigInteger.valueOf(0)

  // gas methods
//  def getGasPool: GasPool = gasPool
  private var gasInTheTank = BigInteger.ZERO
  override def fillGas(gas: BigInteger): Unit = gasInTheTank = gasInTheTank.add(gas)
  override def burnGas(gas: BigInteger): Unit = {
    if (gasInTheTank.compareTo(gas) < 0) {
      throw new OutOfGasException(gas, gasInTheTank)
    }
    gasInTheTank = gasInTheTank.subtract(gas)
  }
}
