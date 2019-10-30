package com.horizen.api.http

import java.time.Instant
import java.util.Optional
import java.util.function.Consumer
import java.{lang, util}

import com.horizen.SidechainTypes
import com.horizen.block.{MainchainBlockReference, SidechainBlock}
import com.horizen.box.{Box, RegularBox}
import com.horizen.companion.SidechainTransactionsCompanion
import com.horizen.node.util.MainchainBlockReferenceInfo
import com.horizen.node.{NodeHistory, NodeMemoryPool, NodeState, NodeWallet, SidechainNodeView}
import com.horizen.params.MainNetParams
import com.horizen.proposition.{Proposition, PublicKey25519Proposition}
import com.horizen.secret.{PrivateKey25519, PrivateKey25519Creator, Secret}
import com.horizen.transaction.{RegularTransaction, TransactionSerializer}
import com.horizen.utils.{ByteArrayWrapper, BytesUtils}
import javafx.util.Pair
import org.mockito.{ArgumentMatchers, Mockito}
import org.scalatest.mockito.MockitoSugar
import scorex.crypto.hash.Blake2b256
import scorex.util.bytesToId
import scorex.util.idToBytes

import scala.collection.JavaConverters._
import scala.collection.mutable
import scala.io.Source
import scala.util.{Failure, Success, Try}

class SidechainNodeViewUtilMocks extends MockitoSugar {

  private val walletBoxesByType = new mutable.LinkedHashMap[Class[_ <: Box[_ <: Proposition]], mutable.Map[ByteArrayWrapper, Box[Proposition]]]()
  private val walletBoxesBalances = new mutable.LinkedHashMap[Class[_ <: Box[_ <: Proposition]], Long]()
  val mainchainBlockReferenceInfoRef = new MainchainBlockReferenceInfo(
    BytesUtils.fromHexString("0000000011aec26c29306d608645a644a592e44add2988a9d156721423e714e0"),
    BytesUtils.fromHexString("00000000106843ee0119c6db92e38e8655452fd85f638f6640475e8c6a3a3582"),
    230, BytesUtils.fromHexString("69c4f36c2b3f546aa57fa03c4df51923e17e8ea59ecfdea7f49c8aff06ec8208"))

  val secret1 = PrivateKey25519Creator.getInstance().generateSecret("testSeed1".getBytes())
  val secret2 = PrivateKey25519Creator.getInstance().generateSecret("testSeed2".getBytes())
  val secret3 = PrivateKey25519Creator.getInstance().generateSecret("testSeed3".getBytes())
  val box_1 = new RegularBox(secret1.publicImage(), 1, 10)
  val box_2 = new RegularBox(secret2.publicImage(), 1, 20)
  val box_3 = new RegularBox(secret3.publicImage(), 1, 30)

  val genesisBlock: SidechainBlock = SidechainBlock.create(bytesToId(new Array[Byte](32)), Instant.now.getEpochSecond - 10000, Seq(), Seq(),
    PrivateKey25519Creator.getInstance().generateSecret("genesis_seed%d".format(6543211L).getBytes),
    SidechainTransactionsCompanion(new util.HashMap[lang.Byte, TransactionSerializer[SidechainTypes#SCBT]]()), null).get

  val allBoxes: util.List[Box[Proposition]] = walletAllBoxes()
  val transactionList: util.List[RegularTransaction] = getTransactionList()

  private def updateBoxesBalance (boxToAdd : Box[Proposition], boxToRemove : Box[Proposition]) : Unit = {
    if (boxToAdd != null) {
      val bca = boxToAdd.getClass
      walletBoxesBalances.put(bca, walletBoxesBalances.getOrElse(bca, 0L) + boxToAdd.value())
    }
    if (boxToRemove != null) {
      val bcr = boxToRemove.getClass
      walletBoxesBalances.put(bcr, walletBoxesBalances.getOrElse(bcr, 0L) - boxToRemove.value())
    }
  }

  private def calculateKey(boxId : Array[Byte]) : ByteArrayWrapper = {
    new ByteArrayWrapper(Blake2b256.hash(boxId))
  }

  private def addWalletBoxByType(walletBox : Box[Proposition]) : Unit = {
    val bc = walletBox.getClass
    val key = calculateKey(walletBox.id())
    val t = walletBoxesByType.get(bc)
    if (t.isEmpty) {
      val m = new mutable.LinkedHashMap[ByteArrayWrapper, Box[Proposition]]()
      m.put(key, walletBox)
      walletBoxesByType.put(bc, m)
    } else
      t.get.put(key, walletBox)
  }

  def getNodeHistoryMock(sidechainApiMockConfiguration: SidechainApiMockConfiguration): NodeHistory = {
    val history: NodeHistory = mock[NodeHistory]

    Mockito.when(history.getBlockById(ArgumentMatchers.any[String])).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getBlockById_return_value()) Optional.of(genesisBlock)
      else Optional.empty())

    Mockito.when(history.getLastBlockIds(ArgumentMatchers.any())).thenAnswer(_ => {
      val ids = new util.ArrayList[String]()
      ids.add("block_id_1")
      ids.add("block_id_2")
      ids.add("block_id_3")
      ids
    })

    Mockito.when(history.getBestBlock).thenAnswer(_ => genesisBlock)

    Mockito.when(history.getBlockIdByHeight(ArgumentMatchers.any())).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getBlockIdByHeight_return_value()) Optional.of("the_block_id")
      else Optional.empty())

    Mockito.when(history.getCurrentHeight).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getCurrentHeight_return_value()) 230
      else 0)

    Mockito.when(history.getBestMainchainBlockReferenceInfo).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getBestMainchainBlockReferenceInfo_return_value())
        Optional.of(mainchainBlockReferenceInfoRef)
      else Optional.empty())

    Mockito.when(history.getMainchainBlockReferenceInfoByMainchainBlockHeight(ArgumentMatchers.any())).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getMainchainBlockReferenceInfoByMainchainBlockHeight_return_value())
        Optional.of(mainchainBlockReferenceInfoRef)
      else Optional.empty())

    Mockito.when(history.getMainchainBlockReferenceInfoByHash(ArgumentMatchers.any())).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getMainchainBlockReferenceInfoByHash_return_value())
        Optional.of(mainchainBlockReferenceInfoRef)
      else Optional.empty())

    Mockito.when(history.getMainchainBlockReferenceByHash(ArgumentMatchers.any())).thenAnswer(_ =>
      if (sidechainApiMockConfiguration.getShould_history_getMainchainBlockReferenceByHash_return_value()) {
        val mcBlockHex = Source.fromResource("mcblock473173").getLines().next()
        val mcBlockBytes = BytesUtils.fromHexString(mcBlockHex)
        MainchainBlockReference.create(mcBlockBytes, new MainNetParams()) match {
          case Success(ref) => Optional.of(ref)
          case Failure(exception) => Optional.empty()
        }
      }
      else Optional.empty())

    Mockito.when(history.searchTransactionInsideBlockchain(ArgumentMatchers.any[String])).thenAnswer(asw => {
      if (sidechainApiMockConfiguration.getShould_history_searchTransactionInBlockchain_return_value()) {
        val id = asw.getArgument(0).asInstanceOf[String]
        Optional.ofNullable(Try(transactionList.asScala.filter(tx => BytesUtils.toHexString(idToBytes(tx.id)).equalsIgnoreCase(id)).head).getOrElse(null))
      } else
        Optional.empty()
    })

    Mockito.when(history.searchTransactionInsideSidechainBlock(ArgumentMatchers.any[String], ArgumentMatchers.any[String])).thenAnswer(asw => {
      if (sidechainApiMockConfiguration.getShould_history_searchTransactionInBlock_return_value()) {
        val id = asw.getArgument(0).asInstanceOf[String]
        Optional.ofNullable(Try(transactionList.asScala.filter(tx => BytesUtils.toHexString(idToBytes(tx.id)).equalsIgnoreCase(id)).head).getOrElse(null))
      } else
        Optional.empty()
    })

    history
  }

  def getNodeStateMock(sidechainApiMockConfiguration: SidechainApiMockConfiguration): NodeState = {
    mock[NodeState]
  }

  private def walletAllBoxes(): util.List[Box[Proposition]] = {
    val list: util.List[Box[Proposition]] = new util.ArrayList[Box[Proposition]]()
    list.add(box_1.asInstanceOf[Box[Proposition]])
    list.add(box_2.asInstanceOf[Box[Proposition]])
    list.add(box_3.asInstanceOf[Box[Proposition]])

    addWalletBoxByType(box_1.asInstanceOf[Box[Proposition]])
    addWalletBoxByType(box_2.asInstanceOf[Box[Proposition]])
    addWalletBoxByType(box_3.asInstanceOf[Box[Proposition]])
    updateBoxesBalance(box_1.asInstanceOf[Box[Proposition]], null)
    updateBoxesBalance(box_2.asInstanceOf[Box[Proposition]], null)
    updateBoxesBalance(box_3.asInstanceOf[Box[Proposition]], null)
    list
  }

  def getNodeWalletMock(sidechainApiMockConfiguration: SidechainApiMockConfiguration): NodeWallet = {
    val wallet: NodeWallet = mock[NodeWallet]
    Mockito.when(wallet.boxesBalance(ArgumentMatchers.any[Class[_ <: Box[_ <: Proposition]]])).thenAnswer(asw =>
      walletBoxesBalances.getOrElse(asw.getArgument(0), 0L))
    Mockito.when(wallet.allBoxesBalance).thenAnswer(_ => allBoxes.asScala.map(_.value()).sum)

    Mockito.when(wallet.allBoxes()).thenAnswer(_ => allBoxes)
    Mockito.when(wallet.allBoxes(ArgumentMatchers.any[util.List[Array[Byte]]])).thenAnswer(asw => {
      val arg = asw.getArgument(0).asInstanceOf[util.List[Array[Byte]]].asScala.map(a=>new String(a)).asJava
      allBoxes.asScala.filter(b => !arg.contains(BytesUtils.toHexString(b.id()))).asJava
    })

    val listOfSecrets = List(secret1, secret2)

    Mockito.when(wallet.secretsOfType(ArgumentMatchers.any[Class[_ <: Secret]])).thenAnswer(asw =>
      listOfSecrets.filter(_.getClass.equals(asw.getArgument(0))).asJava)

    Mockito.when(wallet.walletSeed()).thenAnswer(_ => "a seed".getBytes)

    Mockito.when(wallet.allSecrets()).thenAnswer(_ => listOfSecrets.asJava)

    Mockito.when(wallet.secretByPublicKey(ArgumentMatchers.any[Proposition])).thenAnswer(asw => {
      val prop: Proposition = asw.getArgument(0).asInstanceOf[Proposition]
      if (BytesUtils.toHexString(prop.bytes).equals(BytesUtils.toHexString(secret1.publicImage().bytes))) Optional.of(secret1)
      else if (BytesUtils.toHexString(prop.bytes).equals(BytesUtils.toHexString(secret2.publicImage().bytes))) Optional.of(secret2)
      else if (BytesUtils.toHexString(prop.bytes).equals(BytesUtils.toHexString(secret3.publicImage().bytes))) Optional.of(secret3)
      else Optional.empty()
    })

    Mockito.when(wallet.boxesOfType(ArgumentMatchers.any[Class[_ <: Box[_ <: Proposition]]], ArgumentMatchers.any[java.util.List[Array[Byte]]])).thenAnswer(asw => {
      val idsToExclude = asw.getArgument(1).asInstanceOf[util.List[Array[Byte]]].asScala.map(a=>new String(a)).asJava
      (walletBoxesByType.get(asw.getArgument(0)) match {
        case Some(v) => v.values.toList
        case None => List[Box[Proposition]]()
      }).filter(b => !idsToExclude.contains(BytesUtils.toHexString(b.id()))).asJava
    })

    wallet
  }

  private def getTransaction(fee: Long): RegularTransaction = {
    val from: util.List[Pair[RegularBox, PrivateKey25519]] = new util.ArrayList[Pair[RegularBox, PrivateKey25519]]()
    val to: util.List[Pair[PublicKey25519Proposition, java.lang.Long]] = new util.ArrayList[Pair[PublicKey25519Proposition, java.lang.Long]]()

    from.add(new Pair(box_1, secret1))
    from.add(new Pair(box_2, secret2))

    to.add(new Pair(secret3.publicImage(), 5L))

    RegularTransaction.create(from, to, fee, 1547798549470L)
  }

  private def getTransactionList(): util.List[RegularTransaction] = {
    val list: util.List[RegularTransaction] = new util.ArrayList[RegularTransaction]()
    list.add(getTransaction(1L))
    list.add(getTransaction(1L))
    list
  }

  def getNodeMemoryPoolMock(sidechainApiMockConfiguration: SidechainApiMockConfiguration): NodeMemoryPool = {
    val memoryPool: NodeMemoryPool = mock[NodeMemoryPool]

    Mockito.when(memoryPool.getTransactions).thenAnswer(_ => transactionList)

    Mockito.when(memoryPool.getTransactionsSortedByFee(ArgumentMatchers.any())).thenAnswer(_ => {
      if (sidechainApiMockConfiguration.getShould_history_getTransactionsSortedByFee_return_value())
        transactionList.asScala.sortBy(_.fee()).asJava
      else null
    })

    Mockito.when(memoryPool.getTransactionById(ArgumentMatchers.any[String])).thenAnswer(asw => {
      if (sidechainApiMockConfiguration.getShould_memPool_searchTransactionInMemoryPool_return_value()) {
        val id = asw.getArgument(0).asInstanceOf[String]
        Optional.ofNullable(Try(transactionList.asScala.filter(tx => BytesUtils.toHexString(idToBytes(tx.id)).equalsIgnoreCase(id)).head).getOrElse(null))
      } else
        Optional.empty()
    })

    memoryPool
  }

  def getSidechainNodeView(sidechainApiMockConfiguration: SidechainApiMockConfiguration): SidechainNodeView =
      new SidechainNodeView(
        getNodeHistoryMock(sidechainApiMockConfiguration),
        getNodeStateMock(sidechainApiMockConfiguration),
        getNodeWalletMock(sidechainApiMockConfiguration),
        getNodeMemoryPoolMock(sidechainApiMockConfiguration))

}