package io.horizen.account.state.nativescdata.forgerstakev2.events

import io.horizen.account.state.events.annotation.{Indexed, Parameter}
import io.horizen.evm.Address
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import org.web3j.abi.datatypes.generated.{Bytes1, Bytes32, Uint256, Uint32}
import org.web3j.abi.datatypes.{Address => AbiAddress}

import java.math.BigInteger
import scala.annotation.meta.getter

case class RegisterForger(
    @(Parameter @getter)(1) sender: AbiAddress,
    @(Parameter @getter)(2) @(Indexed @getter) signPubKey: Bytes32,
    @(Parameter @getter)(3) @(Indexed @getter) vrf1: Bytes32,
    @(Parameter @getter)(4) @(Indexed @getter) vrf2: Bytes1,
    @(Parameter @getter)(5) value: Uint256,
    @(Parameter @getter)(6) rewardShare: Uint32,
    @(Parameter @getter)(7) rewardAddress: AbiAddress
)

object RegisterForger {
  def apply(
      sender: Address,
      signPubKey: PublicKey25519Proposition,
      vrfKey: VrfPublicKey,
      value: BigInteger,
      rewardShare: Int,
      rewardAddress: Address
  ): RegisterForger = RegisterForger(
    new AbiAddress(sender.toString),
    new Bytes32(signPubKey.pubKeyBytes()),
    new Bytes32(vrfKey.pubKeyBytes().slice(0, 32)),
    new Bytes1(vrfKey.pubKeyBytes().slice(32, 33)),
    new Uint256(value),
    new Uint32(rewardShare),
    new AbiAddress(rewardAddress.toString)
  )
}
