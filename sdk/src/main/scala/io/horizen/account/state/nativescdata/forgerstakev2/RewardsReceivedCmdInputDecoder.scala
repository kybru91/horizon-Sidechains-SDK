package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.proposition.PublicKey25519Proposition
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Uint32}
import org.web3j.abi.datatypes.{StaticStruct, Type}

import java.util

object RewardsReceivedCmdInputDecoder
    extends ABIDecoder[RewardsReceivedCmdInput]
    with MsgProcessorInputDecoder[RewardsReceivedCmdInput]
    with VRFDecoder {

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(
      util.Arrays.asList(
        new TypeReference[Bytes32]() {},
        new TypeReference[Bytes32]() {},
        new TypeReference[Bytes1]() {},
        new TypeReference[Uint32]() {},
        new TypeReference[Uint32]() {},
      ),
    )

  override def createType(listOfParams: util.List[Type[_]]): RewardsReceivedCmdInput = {
    val forgerPublicKey = new PublicKey25519Proposition(listOfParams.get(0).asInstanceOf[Bytes32].getValue)
    val vrfKey = decodeVrfKey(listOfParams.get(1).asInstanceOf[Bytes32], listOfParams.get(2).asInstanceOf[Bytes1])
    val forgerPublicKeys = ForgerPublicKeys(forgerPublicKey, vrfKey)
    val consensusEpochStart = listOfParams.get(3).asInstanceOf[Uint32].getValue.intValueExact()
    val maxNumOfEpoch = listOfParams.get(4).asInstanceOf[Uint32].getValue.intValueExact()
    RewardsReceivedCmdInput(forgerPublicKeys, consensusEpochStart, maxNumOfEpoch)
  }

}

case class RewardsReceivedCmdInput(
  forgerPublicKeys: ForgerPublicKeys,
  consensusEpochStart: Int,
  maxNumOfEpoch: Int,
) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {
    val forgerPublicKeysAbi = forgerPublicKeys.asABIType()
    val listOfParams: util.List[Type[_]] =
      new util.ArrayList(forgerPublicKeysAbi.getValue.asInstanceOf[util.List[Type[_]]])
    listOfParams.add(new Uint32(consensusEpochStart))
    listOfParams.add(new Uint32(maxNumOfEpoch))
    new StaticStruct(listOfParams)
  }

  override def toString: String =
    "%s(forgerPubKeys: %s)"
      .format(this.getClass.toString, forgerPublicKeys)
}
