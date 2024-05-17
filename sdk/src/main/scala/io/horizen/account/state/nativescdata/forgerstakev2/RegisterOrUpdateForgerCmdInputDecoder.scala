package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.account.state.ForgerStakeV2MsgProcessor.MAX_REWARD_SHARE
import io.horizen.evm.Address
import io.horizen.proof.{Signature25519, VrfProof}
import io.horizen.proposition.PublicKey25519Proposition
import io.horizen.utils.Ed25519
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Uint32}
import org.web3j.abi.datatypes.{StaticStruct, Type, Address => AbiAddress}

import java.util

object RegisterOrUpdateForgerCmdInputDecoder
  extends ABIDecoder[RegisterOrUpdateForgerCmdInput]
    with MsgProcessorInputDecoder[RegisterOrUpdateForgerCmdInput]
    with VRFDecoder{

  val NULL_ADDRESS_WITH_PREFIX_HEX_STRING : String = "0x0000000000000000000000000000000000000000"

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Bytes32]() {}, // blockSignPublicKey
      new TypeReference[Bytes32]() {}, // vrfKey
      new TypeReference[Bytes1]() {},
      new TypeReference[Uint32]() {}, // rewardShare
      new TypeReference[AbiAddress]() {}, // smart contract address
      new TypeReference[Bytes32]() {}, // sign1 64 bytes
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {}, // sign2 97 bytes
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes32]() {},
      new TypeReference[Bytes1]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): RegisterOrUpdateForgerCmdInput = {
    val blockSignPublicKey = new PublicKey25519Proposition(listOfParams.get(0).asInstanceOf[Bytes32].getValue)
    val vrfKey = decodeVrfKey(listOfParams.get(1).asInstanceOf[Bytes32], listOfParams.get(2).asInstanceOf[Bytes1])
    val forgerPublicKeys = ForgerPublicKeys(blockSignPublicKey, vrfKey)
    val rewardShare = listOfParams.get(3).asInstanceOf[Uint32].getValue.intValueExact()
    val smartcontractAddress = new Address(listOfParams.get(4).asInstanceOf[AbiAddress].toString)
    val sign1 = new Signature25519(listOfParams.get(5).asInstanceOf[Bytes32].getValue ++ listOfParams.get(6).asInstanceOf[Bytes32].getValue)
    val sign2 = new VrfProof(
      listOfParams.get(7).asInstanceOf[Bytes32].getValue ++ listOfParams.get(8).asInstanceOf[Bytes32].getValue ++
    listOfParams.get(9).asInstanceOf[Bytes32].getValue ++ listOfParams.get(10).asInstanceOf[Bytes1].getValue)

    RegisterOrUpdateForgerCmdInput(forgerPublicKeys, rewardShare, smartcontractAddress, sign1, sign2)
  }

}

case class RegisterOrUpdateForgerCmdInput(forgerPublicKeys: ForgerPublicKeys, rewardShare: Int,
                                          rewardAddress: Address,
                                          signature25519: Signature25519, signatureVrf: VrfProof)
  extends ABIEncodable[StaticStruct]
    with VRFDecoder{
  require(rewardShare >= 0, "reward share expected to be non negative.")
  require(rewardShare <= MAX_REWARD_SHARE, s"reward share expected to be $MAX_REWARD_SHARE at most")

  override def asABIType(): StaticStruct = {

    val listOfParams: util.List[Type[_]] = new util.ArrayList()

    val vrfPublicKeyBytes = vrfPublicKeyToAbi(forgerPublicKeys.vrfPublicKey.pubKeyBytes())
    val sign1Bytes = signature25519.bytes
    val sign2Bytes = signatureVrf.bytes

    listOfParams.add(new Bytes32(forgerPublicKeys.blockSignPublicKey.bytes()))
    listOfParams.add(vrfPublicKeyBytes._1)
    listOfParams.add(vrfPublicKeyBytes._2)
    listOfParams.add(new Uint32(rewardShare))
    listOfParams.add(new AbiAddress(rewardAddress.toString))
    listOfParams.add(new Bytes32(util.Arrays.copyOfRange(sign1Bytes, 0, 32)))
    listOfParams.add(new Bytes32(util.Arrays.copyOfRange(sign1Bytes, 32, Ed25519.signatureLength())))
    listOfParams.add(new Bytes32(util.Arrays.copyOfRange(sign2Bytes, 0, 32)))
    listOfParams.add(new Bytes32(util.Arrays.copyOfRange(sign2Bytes, 32, 64)))
    listOfParams.add(new Bytes32(util.Arrays.copyOfRange(sign2Bytes, 64, 96)))
    listOfParams.add(new Bytes1(util.Arrays.copyOfRange(sign2Bytes, 96, VrfProof.PROOF_LENGTH)))

    new StaticStruct(listOfParams)
  }

  override def toString: String = "%s(forgerPubKeys: %s, rewardShare: %d, rewardsAddress: %s, sign1: %s, sign2: %s)"
    .format(this.getClass.toString, forgerPublicKeys, rewardShare, rewardAddress, signature25519, signatureVrf)
}
