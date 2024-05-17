package io.horizen.account.network

import com.fasterxml.jackson.annotation.JsonView
import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import io.horizen.account.proposition.{AddressProposition, AddressPropositionSerializer}
import io.horizen.account.state.nativescdata.forgerstakev2.{ForgerInfoABI, VRFDecoder}
import io.horizen.account.state.{ForgerPublicKeys, ForgerPublicKeysSerializer}
import io.horizen.evm.Address
import io.horizen.json.Views
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Int32, Uint32}
import org.web3j.abi.datatypes.{DynamicArray, DynamicStruct, StaticStruct, Type, Address => AbiAddress}
import sparkz.core.serialization.{BytesSerializable, SparkzSerializer}
import sparkz.util.serialization.{Reader, Writer}

import java.util
import scala.collection.JavaConverters
import scala.collection.convert.ImplicitConversions.`collection AsScalaIterable`


case class PagedForgersOutput(nextStartPos: Int, listOfForgerInfo: Seq[ForgerInfo])
  extends ABIEncodable[DynamicStruct] {

  override def asABIType(): DynamicStruct = {

    val seqOfStruct = listOfForgerInfo.map(_.asABIType())
    val listOfStruct = JavaConverters.seqAsJavaList(seqOfStruct)
    val theType = classOf[StaticStruct]
    val listOfParams: util.List[Type[_]] = util.Arrays.asList(
      new Int32(nextStartPos),
      new DynamicArray(theType, listOfStruct)
    )
    new DynamicStruct(listOfParams)

  }

  override def toString: String = "%s(startPos: %s, ForgerInfo: %s)"
    .format(
      this.getClass.toString,
      nextStartPos, listOfForgerInfo)
}


object PagedForgersOutputDecoder
  extends ABIDecoder[PagedForgersOutput]
    with MsgProcessorInputDecoder[PagedForgersOutput]{

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Int32]() {},
      new TypeReference[DynamicArray[ForgerInfoABI]]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): PagedForgersOutput = {
    val nextStartPos = listOfParams.get(0).asInstanceOf[Int32].getValue.intValueExact()
    val listOfStaticStruct = listOfParams.get(1).asInstanceOf[DynamicArray[ForgerInfoABI]].getValue
    val listOfForgerInfo = listOfStaticStruct.map(ForgerInfo(_))

    PagedForgersOutput(nextStartPos, listOfForgerInfo.toSeq)
  }

}

object GetForgerOutputDecoder
  extends ABIDecoder[ForgerInfo]
    with MsgProcessorInputDecoder[ForgerInfo]
    with VRFDecoder{

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes1]() {},
      new TypeReference[Uint32]() {},
      new TypeReference[AbiAddress]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): ForgerInfo = {
    val forgerPublicKey = new PublicKey25519Proposition(listOfParams.get(0).asInstanceOf[Bytes32].getValue)
    val vrfKey = decodeVrfKey(listOfParams.get(1).asInstanceOf[Bytes32], listOfParams.get(2).asInstanceOf[Bytes1])
    val forgerPublicKeys = ForgerPublicKeys(forgerPublicKey, vrfKey)
    val rewardShare = listOfParams.get(3).asInstanceOf[Uint32].getValue.intValueExact()
    val rewardAddress = new Address(listOfParams.get(4).asInstanceOf[AbiAddress].toString)

    ForgerInfo(forgerPublicKeys, rewardShare, new AddressProposition(rewardAddress))
  }

}


@JsonView(Array(classOf[Views.Default]))
case class ForgerInfo(forgerPublicKeys: ForgerPublicKeys,
                      rewardShare:Int,
                      rewardAddress: AddressProposition)
  extends BytesSerializable with ABIEncodable[StaticStruct]  {

  require(rewardShare > -1, "rewardShare expected to be non negative.")

  override type M = ForgerInfo

  override def serializer: SparkzSerializer[ForgerInfo] = ForgerInfoSerializer

  override def toString: String = "%s(forgerPublicKeys: %s, rewardShare: %s, rewardAddress: %s)"
    .format(this.getClass.toString,  forgerPublicKeys, rewardShare, rewardAddress)


  private[horizen] def asABIType(): StaticStruct = {
    val forgerPublicKeysAbi = forgerPublicKeys.asABIType()
    val listOfParams: util.List[Type[_]] = new util.ArrayList(forgerPublicKeysAbi.getValue.asInstanceOf[util.List[Type[_]]])
    listOfParams.add(new Uint32(rewardShare))
    listOfParams.add(new AbiAddress(rewardAddress.address().toString))
    new StaticStruct(listOfParams)
  }
}


object ForgerInfo {
  def apply(forgerInfoABI: ForgerInfoABI): ForgerInfo =
    ForgerInfo(
      ForgerPublicKeys(new PublicKey25519Proposition(forgerInfoABI.pubKey),
        new VrfPublicKey(forgerInfoABI.vrf1 ++ forgerInfoABI.vrf2)),
      forgerInfoABI.rewardShare,
      new AddressProposition(new Address(forgerInfoABI.rewardAddress))
    )

}

object ForgerInfoSerializer extends SparkzSerializer[ForgerInfo] {
  override def serialize(s: ForgerInfo, w: Writer): Unit = {
    ForgerPublicKeysSerializer.serialize(s.forgerPublicKeys, w)
    w.putInt(s.rewardShare)
    AddressPropositionSerializer.getSerializer.serialize(s.rewardAddress, w)
  }

  override def parse(r: Reader): ForgerInfo = {
    val forgerPublicKeys = ForgerPublicKeysSerializer.parse(r)
    val rewardShare = r.getInt()
    val rewardAddress = AddressPropositionSerializer.getSerializer.parse(r)
    ForgerInfo(forgerPublicKeys, rewardShare, rewardAddress)
  }
}
