package io.horizen.account.state.nativescdata.forgerstakev2


import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.account.state.nativescdata.forgerstakev2.StakeTotalCmdInputDecoder.{emptyAddressPlaceholder, emptyForgerPublicKeysPlaceholder, emptyIntPlaceholder}
import io.horizen.evm.Address
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Uint32}
import org.web3j.abi.datatypes.{StaticStruct, Type, Address => AbiAddress}

import java.util

object StakeTotalCmdInputDecoder
  extends ABIDecoder[StakeTotalCmdInput]
    with MsgProcessorInputDecoder[StakeTotalCmdInput]
    with VRFDecoder{

  val emptyForgerPublicKeysPlaceholder: ForgerPublicKeys = {
    ForgerPublicKeys(
      new PublicKey25519Proposition(new Array[Byte](PublicKey25519Proposition.KEY_LENGTH)),
      new VrfPublicKey(new Array[Byte](VrfPublicKey.KEY_LENGTH))
    )
  }
  val emptyAddressPlaceholder: Address = Address.ZERO
  val emptyIntPlaceholder: Int = 0

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes1]() {},
      new TypeReference[AbiAddress]() {},
      new TypeReference[Uint32]() {},
      new TypeReference[Uint32]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): StakeTotalCmdInput = {
    val forgerPublicKey = new PublicKey25519Proposition(listOfParams.get(0).asInstanceOf[Bytes32].getValue)
    val vrfKey = decodeVrfKey(listOfParams.get(1).asInstanceOf[Bytes32], listOfParams.get(2).asInstanceOf[Bytes1])
    val forgerPublicKeys = Some(ForgerPublicKeys(forgerPublicKey, vrfKey)).filter(_ != emptyForgerPublicKeysPlaceholder)
    val delegator = Some(new Address(listOfParams.get(3).asInstanceOf[AbiAddress].toString)).filter(_ != emptyAddressPlaceholder)
    val consensusEpochStart = Some(listOfParams.get(4).asInstanceOf[Uint32].getValue.intValueExact()).filter(_ != emptyIntPlaceholder)
    val maxNumOfEpoch = Some(listOfParams.get(5).asInstanceOf[Uint32].getValue.intValueExact()).filter(_ != emptyIntPlaceholder)
    StakeTotalCmdInput(forgerPublicKeys, delegator, consensusEpochStart, maxNumOfEpoch)
  }

}

case class StakeTotalCmdInput(forgerPublicKeys: Option[ForgerPublicKeys], delegator: Option[Address], consensusEpochStart: Option[Int], maxNumOfEpoch: Option[Int]) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {
    val forgerPublicKeysAbi = forgerPublicKeys.getOrElse(emptyForgerPublicKeysPlaceholder).asABIType()
    val listOfParams: util.List[Type[_]] = new util.ArrayList(forgerPublicKeysAbi.getValue.asInstanceOf[util.List[Type[_]]])
    listOfParams.add(new AbiAddress(delegator.getOrElse(emptyAddressPlaceholder).toString))
    listOfParams.add(new Uint32(consensusEpochStart.getOrElse(emptyIntPlaceholder)))
    listOfParams.add(new Uint32(maxNumOfEpoch.getOrElse(emptyIntPlaceholder)))
    new StaticStruct(listOfParams)
  }

  override def toString: String = "%s(forgerPubKeys: %s, delegator: %s, consensusEpochStart: %s, maxNumOfEpoch: %s)"
    .format(this.getClass.toString, forgerPublicKeys, delegator, consensusEpochStart, maxNumOfEpoch)
}
