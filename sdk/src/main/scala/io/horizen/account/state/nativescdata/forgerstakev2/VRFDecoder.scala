package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.proposition.VrfPublicKey
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32}

import java.util

trait VRFDecoder {

  protected[horizen] def decodeVrfKey(vrfFirst32Bytes: Bytes32, vrfLastByte: Bytes1): VrfPublicKey = {
    val vrfinBytes = vrfFirst32Bytes.getValue ++ vrfLastByte.getValue
    new VrfPublicKey(vrfinBytes)
  }

  protected[horizen] def vrfPublicKeyToAbi(vrfPublicKey: Array[Byte]): (Bytes32, Bytes1) = {
    val vrfPublicKeyFirst32Bytes = new Bytes32(util.Arrays.copyOfRange(vrfPublicKey, 0, 32))
    val vrfPublicKeyLastByte = new Bytes1(Array[Byte](vrfPublicKey(32)))
    (vrfPublicKeyFirst32Bytes, vrfPublicKeyLastByte)
  }
}
