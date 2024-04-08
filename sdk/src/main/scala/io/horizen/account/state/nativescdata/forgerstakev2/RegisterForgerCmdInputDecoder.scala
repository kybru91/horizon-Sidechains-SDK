package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.evm.Address
import io.horizen.proof.{Signature25519, VrfProof}
import io.horizen.proposition.PublicKey25519Proposition
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.{StaticStruct, Type, Address => AbiAddress}
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Int32, Uint32}

import java.util

object RegisterForgerCmdInputDecoder
  extends ABIDecoder[RegisterForgerCmdInput]
    with MsgProcessorInputDecoder[RegisterForgerCmdInput]
    with VRFDecoder{

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes1]() {},
      new TypeReference[Uint32]() {},
      new TypeReference[AbiAddress]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): RegisterForgerCmdInput = {
    val blockSignPublicKey = new PublicKey25519Proposition(listOfParams.get(0).asInstanceOf[Bytes32].getValue)
    val vrfKey = decodeVrfKey(listOfParams.get(1).asInstanceOf[Bytes32], listOfParams.get(2).asInstanceOf[Bytes1])
    val forgerPublicKeys = ForgerPublicKeys(blockSignPublicKey, vrfKey)
    val rewardShare = listOfParams.get(3).asInstanceOf[Uint32].getValue.intValueExact()
    val smartcontractAddress = new Address(listOfParams.get(4).asInstanceOf[AbiAddress].toString)
    val sign1 = new Signature25519(listOfParams.get(5).asInstanceOf[Bytes32].getValue ++ listOfParams.get(6).asInstanceOf[Bytes32].getValue)
    val sign2 = new VrfProof(listOfParams.get(7).asInstanceOf[Bytes32].getValue ++ listOfParams.get(8).asInstanceOf[Bytes32].getValue)

    RegisterForgerCmdInput(forgerPublicKeys, rewardShare, smartcontractAddress, sign1, sign2)
  }

}

case class RegisterForgerCmdInput(forgerPublicKeys: ForgerPublicKeys, rewardShare: Int,
                                  smartContractAddress: Address,
                                  signature25519: Signature25519, signatureVrf: VrfProof) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {
    val listOfParams: util.List[Type[_]] = new util.ArrayList(
      forgerPublicKeys.asABIType().getValue.asInstanceOf[util.List[Type[_]]]
    )
    // TODO listOfParams.add(new Int32(startIndex))
    new StaticStruct(listOfParams)
  }

  override def toString: String = "%s(forgerPubKeys: %s)"
    .format(this.getClass.toString, forgerPublicKeys)
}
