package io.horizen.account.state

import io.horizen.account.proposition.AddressPropositionSerializer
import io.horizen.account.utils.ForgerIdentifier
import io.horizen.proposition.{PublicKey25519PropositionSerializer, VrfPublicKeySerializer}
import sparkz.core.serialization.SparkzSerializer
import sparkz.util.serialization.{Reader, Writer}

import java.math.BigInteger

object McForgerPoolRewardsSerializer extends SparkzSerializer[Map[ForgerIdentifier, BigInteger]] {
  final val SERIALIZATION_FORMAT_1_4_FLAG = -1
  private val addressSerializer: AddressPropositionSerializer = AddressPropositionSerializer.getSerializer
  private val signPubKeySerializer: PublicKey25519PropositionSerializer =
    PublicKey25519PropositionSerializer.getSerializer
  private val vrfPubKeySerializer: VrfPublicKeySerializer = VrfPublicKeySerializer.getSerializer

  override def serialize(forgerPoolRewards: Map[ForgerIdentifier, BigInteger], w: Writer): Unit = {
    w.putInt(forgerPoolRewards.size)
    forgerPoolRewards.foreach { case (forgerIdentifier, reward) =>
      addressSerializer.serialize(forgerIdentifier.getAddress, w)
      if (forgerIdentifier.getForgerKeys.isDefined) {
        w.putInt(SERIALIZATION_FORMAT_1_4_FLAG) //flag to indicate new serialization format is used
        forgerIdentifier.getForgerKeys.foreach { keys =>
          signPubKeySerializer.serialize(keys.blockSignPublicKey, w)
          vrfPubKeySerializer.serialize(keys.vrfPublicKey, w)
        }
        w.putInt(reward.toByteArray.length)
        w.putBytes(reward.toByteArray)
      }
      else {
        w.putInt(reward.toByteArray.length)
        w.putBytes(reward.toByteArray)
      }
    }
  }

  override def parse(r: Reader): Map[ForgerIdentifier, BigInteger] = {
    val length = r.getInt()
    (1 to length).map { _ =>
      val address = addressSerializer.parse(r)
      val valueLength: Int = r.getInt
      if (valueLength == SERIALIZATION_FORMAT_1_4_FLAG) {
        val blockSignPublicKey = signPubKeySerializer.parse(r)
        val vrfPublicKey = vrfPubKeySerializer.parse(r)
        val rewardLength: Int = r.getInt
        val reward: BigInteger = new BigInteger(r.getBytes(rewardLength))
        (new ForgerIdentifier(address, Some(ForgerPublicKeys(blockSignPublicKey, vrfPublicKey))), reward)
      }
      else {
        val reward: BigInteger = new BigInteger(r.getBytes(valueLength))
        (new ForgerIdentifier(address), reward)
      }
    }.toMap
  }

}
