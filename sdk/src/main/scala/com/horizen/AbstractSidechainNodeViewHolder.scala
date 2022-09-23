package com.horizen

import com.horizen.block.{SidechainBlockBase, SidechainBlockHeaderBase}
import com.horizen.node._
import com.horizen.params.NetworkParams
import com.horizen.storage.{AbstractHistoryStorage, SidechainStorageInfo}
import com.horizen.transaction.Transaction
import com.horizen.validation._
import sparkz.core.consensus.History.ProgressInfo
import sparkz.core.idToVersion
import sparkz.core.network.NodeViewSynchronizer.ReceivableMessages._
import sparkz.core.utils.NetworkTimeProvider
import sparkz.core.settings.SparkzSettings
import scala.util.{Failure, Success, Try}

abstract class AbstractSidechainNodeViewHolder[
  TX <: Transaction, H <: SidechainBlockHeaderBase, PMOD <: SidechainBlockBase[TX, H]]
(
  sidechainSettings: SidechainSettings,
  params: NetworkParams,
  timeProvider: NetworkTimeProvider
)
  extends sparkz.core.NodeViewHolder[TX, PMOD]
    with SidechainTypes {
  override type SI = SidechainSyncInfo
  type HSTOR <: AbstractHistoryStorage[PMOD, HSTOR]

  override type HIS <: AbstractHistory[TX, H, PMOD, HSTOR, HIS]
  override type VL <: Wallet[SidechainTypes#SCS, SidechainTypes#SCP, TX, PMOD, VL]

  protected var applyingBlock: Boolean = false

  val maxTxFee = sidechainSettings.wallet.maxTxFee
  val listOfStorageInfo: Seq[SidechainStorageInfo]

  case class SidechainNodeUpdateInformation(history: HIS,
                                            state: MS,
                                            wallet: VL,
                                            failedMod: Option[PMOD],
                                            alternativeProgressInfo: Option[ProgressInfo[PMOD]],
                                            suffix: IndexedSeq[PMOD])

  override val sparksSettings: SparkzSettings = sidechainSettings.sparkzSettings

  protected def semanticBlockValidators(params: NetworkParams): Seq[SemanticBlockValidator[PMOD]] = Seq(new SidechainBlockSemanticValidator[TX, PMOD](params))

  protected def historyBlockValidators(params: NetworkParams): Seq[HistoryBlockValidator[TX, H, PMOD, HSTOR, HIS]] = Seq(
    new WithdrawalEpochValidator(params),
    new MainchainPoWValidator(params),
    new MainchainBlockReferenceValidator(params),
    new ConsensusValidator(timeProvider)
  )

  def dumpStorages: Unit

  def getStorageVersions: Map[String, String]

  override def receive: Receive = {
    applyFunctionOnNodeView orElse
      applyBiFunctionOnNodeView orElse
      getCurrentSidechainNodeViewInfo orElse
      processLocallyGeneratedSecret orElse
      processRemoteModifiers orElse
      applyModifier orElse
      processGetStorageVersions orElse
      processLocallyGeneratedTransaction orElse
      super.receive
  }

  protected def getCurrentSidechainNodeViewInfo: Receive

  protected def applyFunctionOnNodeView: Receive

  protected def applyBiFunctionOnNodeView[T, A]: Receive

  /**
   * Process new modifiers from remote.
   * Put all candidates to modifiersCache and then try to apply as much modifiers from cache as possible.
   * Clear cache if it's size exceeds size limit.
   * Publish `ModifiersProcessingResult` message with all just applied and removed from cache modifiers.
   */
  override def processRemoteModifiers: Receive = {
    case sparkz.core.NodeViewHolder.ReceivableMessages.ModifiersFromRemote(mods: Seq[PMOD]) =>
      mods.foreach(m => modifiersCache.put(m.id, m))

      log.debug(s"Cache size before: ${modifiersCache.size}")

      if (!applyingBlock) {
        applyingBlock = true
        self ! AbstractSidechainNodeViewHolder.InternalReceivableMessages.ApplyModifier(Seq())
      }
  }

  protected def processLocallyGeneratedSecret: Receive = {
    case AbstractSidechainNodeViewHolder.ReceivableMessages.LocallyGeneratedSecret(secret) =>
      vault().addSecret(secret) match {
        case Success(newVault) =>
          updateNodeView(updatedVault = Some(newVault))
          sender() ! Success(Unit)
        case Failure(ex) =>
          sender() ! Failure(ex)
      }
  }

  def applyModifier: Receive = {
    case AbstractSidechainNodeViewHolder.InternalReceivableMessages.ApplyModifier(applied: Seq[PMOD]) => {
      modifiersCache.popCandidate(history()) match {
        case Some(mod) =>
          pmodModify(mod)
          self ! AbstractSidechainNodeViewHolder.InternalReceivableMessages.ApplyModifier(mod +: applied)
        case None => {
          val cleared = modifiersCache.cleanOverfull()
          context.system.eventStream.publish(ModifiersProcessingResult(applied, cleared))
          applyingBlock = false
          log.debug(s"Cache size after: ${modifiersCache.size}")
        }
      }
    }
  }

  def processGetStorageVersions: Receive = {
    case AbstractSidechainNodeViewHolder.ReceivableMessages.GetStorageVersions =>
      sender() ! getStorageVersions
  }

  def processLocallyGeneratedTransaction: Receive


  // This method is actually a copy-paste of parent NodeViewHolder.pmodModify method.
  // The difference is that modifiers are applied to the State and Wallet simultaneously.
  override protected def pmodModify(pmod: PMOD): Unit = {
    if (!history().contains(pmod.id)) {
      context.system.eventStream.publish(StartingPersistentModifierApplication(pmod))

      log.info(s"Apply modifier ${pmod.encodedId} of type ${pmod.modifierTypeId} to nodeViewHolder")

      history().append(pmod) match {
        case Success((historyBeforeStUpdate, progressInfo)) =>
          log.debug(s"Going to apply modifications to the state: $progressInfo")
          context.system.eventStream.publish(SyntacticallySuccessfulModifier(pmod))
          context.system.eventStream.publish(NewOpenSurface(historyBeforeStUpdate.openSurfaceIds()))

          if (progressInfo.toApply.nonEmpty) {
            val (newHistory, newStateTry, newWallet, blocksApplied) =
              updateStateAndWallet(historyBeforeStUpdate, minimalState(), vault(), progressInfo, IndexedSeq())

            newStateTry match {
              case Success(newState) =>
                val newMemPool = updateMemPool(progressInfo.toRemove, blocksApplied, memoryPool(), newState)
                // Note: in parent NodeViewHolder.pmodModify wallet was updated here.

                log.info(s"Persistent modifier ${pmod.encodedId} applied successfully")
                updateNodeView(Some(newHistory), Some(newState), Some(newWallet), Some(newMemPool))


              case Failure(e) =>
                log.warn(s"Can`t apply persistent modifier (id: ${pmod.encodedId}, contents: $pmod) to minimal state", e)
                updateNodeView(updatedHistory = Some(newHistory))
                context.system.eventStream.publish(SemanticallyFailedModification(pmod, e))
            }
          } else {
            updateNodeView(updatedHistory = Some(historyBeforeStUpdate))
          }
        case Failure(e) =>
          log.warn(s"Can`t apply persistent modifier (id: ${pmod.encodedId}, contents: $pmod) to history", e)
          context.system.eventStream.publish(SyntacticallyFailedModification(pmod, e))
      }
    } else {
      log.warn(s"Trying to apply modifier ${pmod.encodedId} that's already in history")
    }
  }

  // This method is actually a copy-paste of parent NodeViewHolder.updateState method.
  // The difference is that State is updated together with Wallet.
  def updateStateAndWallet(history: HIS,
                                   state: MS,
                                   wallet: VL,
                                   progressInfo: ProgressInfo[PMOD],
                                   suffixApplied: IndexedSeq[PMOD]): (HIS, Try[MS], VL, Seq[PMOD]) = {

    // Do rollback if chain switchapplyStateAndWallet needed
    val (stateToApplyTry: Try[MS], walletToApplyTry: Try[VL], suffixTrimmed: IndexedSeq[PMOD]) = if (progressInfo.chainSwitchingNeeded) {
      @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
      val branchingPoint = progressInfo.branchPoint.get //todo: .get
      if (state.version != branchingPoint) {
        (
          state.rollbackTo(idToVersion(branchingPoint)),
          wallet.rollback(idToVersion(branchingPoint)),
          trimChainSuffix(suffixApplied, branchingPoint)
        )
      } else (Success(state), Success(wallet), IndexedSeq())
    } else (Success(state), Success(wallet), suffixApplied)

    (stateToApplyTry, walletToApplyTry) match {
      case (Success(stateToApply), Success(walletToApply)) =>
        val nodeUpdateInfo = applyStateAndWallet(history, stateToApply, walletToApply, suffixTrimmed, progressInfo).get

        nodeUpdateInfo.failedMod match {
          case Some(_) =>
            @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
            val alternativeProgressInfo = nodeUpdateInfo.alternativeProgressInfo.get
            updateStateAndWallet(nodeUpdateInfo.history, nodeUpdateInfo.state, nodeUpdateInfo.wallet, alternativeProgressInfo, nodeUpdateInfo.suffix)
          case None => (nodeUpdateInfo.history, Success(nodeUpdateInfo.state), nodeUpdateInfo.wallet, nodeUpdateInfo.suffix)
        }
      case (Failure(e), _) =>
        log.error("State rollback failed: ", e)
        context.system.eventStream.publish(RollbackFailed)
        //todo: what to return here? the situation is totally wrong
        ???
      case (_, Failure(e)) =>
        log.error("Wallet rollback failed: ", e)
        context.system.eventStream.publish(RollbackFailed)
        //todo: what to return here? the situation is totally wrong
        ???
    }
  }

  // This method is actually a copy-paste of parent NodeViewHolder.trimChainSuffix method.
  protected def trimChainSuffix(suffix: IndexedSeq[PMOD], rollbackPoint: scorex.util.ModifierId): IndexedSeq[PMOD] = {
    val idx = suffix.indexWhere(_.id == rollbackPoint)
    if (idx == -1) IndexedSeq() else suffix.drop(idx)
  }


  // Apply state and wallet with blocks one by one, if consensus epoch is going to be changed -> notify wallet and history.
  protected def applyStateAndWallet(history: HIS,
                                    stateToApply: MS,
                                    walletToApply: VL,
                                    suffixTrimmed: IndexedSeq[PMOD],
                                    progressInfo: ProgressInfo[PMOD]): Try[SidechainNodeUpdateInformation] = Try {
    val updateInfoSample = SidechainNodeUpdateInformation(history, stateToApply, walletToApply, None, None, suffixTrimmed)
    progressInfo.toApply.foldLeft(updateInfoSample) { case (updateInfo, modToApply) =>
      if (updateInfo.failedMod.isEmpty) {
        val (newHistory, newWallet) = applyConsensusEpochInfo(updateInfo.history, updateInfo.state, updateInfo.wallet, modToApply)

        updateInfo.state.applyModifier(modToApply) match {
          case Success(stateAfterApply) =>
            val historyAfterApply = newHistory.reportModifierIsValid(modToApply).get
            context.system.eventStream.publish(SemanticallySuccessfulModifier(modToApply))

            val (historyAfterUpdateFee, walletAfterApply) = scanBlockWithFeePayments(historyAfterApply, stateAfterApply, newWallet, modToApply)
            SidechainNodeUpdateInformation(historyAfterUpdateFee, stateAfterApply, walletAfterApply, None, None, updateInfo.suffix :+ modToApply)

          case Failure(e) =>
            log.error(s"Failed to apply block ${modToApply.id} to the state.", e)
            val (historyAfterApply, newProgressInfo) = newHistory.reportModifierIsInvalid(modToApply, progressInfo).get
            context.system.eventStream.publish(SemanticallyFailedModification(modToApply, e))
            SidechainNodeUpdateInformation(historyAfterApply, updateInfo.state, newWallet, Some(modToApply), Some(newProgressInfo), updateInfo.suffix)
        }
      } else updateInfo
    }
  }


  // Check if the next modifier will change Consensus Epoch, so notify History and Wallet with current info.
  protected def applyConsensusEpochInfo(history: HIS, state: MS, wallet: VL, modToApply: PMOD): (HIS, VL)

  // Check is the modifier ends the withdrawal epoch, so notify History and Wallet about fees to be payed.
  // Scan modifier by the Wallet considering the forger fee payments.
  protected def scanBlockWithFeePayments(history: HIS, state: MS, wallet: VL, modToApply: PMOD): (HIS, VL)



}

object AbstractSidechainNodeViewHolder {
  object ReceivableMessages {
    case class GetDataFromCurrentSidechainNodeView[TX <: Transaction,
      H <: SidechainBlockHeaderBase,
      PMOD <: SidechainBlockBase[TX, H],
      NH <: NodeHistoryBase[TX, H, PMOD],
      NS <: NodeStateBase,
      NW <: NodeWalletBase,
      NP <: NodeMemoryPoolBase[TX],
      NV <: SidechainNodeViewBase[TX, H, PMOD, NH, NS, NW, NP],
      A](f: NV => A)

    case class LocallyGeneratedSecret[S <: SidechainTypes#SCS](secret: S)

    case class ApplyFunctionOnNodeView[TX <: Transaction,
      H <: SidechainBlockHeaderBase,
      PMOD <: SidechainBlockBase[TX, H],
      NH <: NodeHistoryBase[TX, H, PMOD],
      NS <: NodeStateBase,
      NW <: NodeWalletBase,
      NP <: NodeMemoryPoolBase[TX],
      NV <: SidechainNodeViewBase[TX, H, PMOD, NH, NS, NW, NP],
      A](f: java.util.function.Function[NV, A])

    case class ApplyBiFunctionOnNodeView[
      TX <: Transaction,
      H <: SidechainBlockHeaderBase,
      PMOD <: SidechainBlockBase[TX, H],
      NH <: NodeHistoryBase[TX, H, PMOD],
      NS <: NodeStateBase,
      NW <: NodeWalletBase,
      NP <: NodeMemoryPoolBase[TX],
      NV <: SidechainNodeViewBase[TX, H, PMOD, NH, NS, NW, NP],
      T,
      A](f: java.util.function.BiFunction[NV, T, A], functionParameter: T)

    case object GetStorageVersions

  }

  protected[horizen] object InternalReceivableMessages {
    case class ApplyModifier[PMOD](applied: Seq[PMOD])

    sealed trait NewLocallyGeneratedTransactions[TX <: Transaction] {
      val txs: Iterable[TX]
    }

    case class LocallyGeneratedTransaction[TX <: Transaction](tx: TX) extends NewLocallyGeneratedTransactions[TX] {
      override val txs: Iterable[TX] = Iterable(tx)
    }
  }

}


