package io.horizen.account.state

import io.horizen.account.proposition.AddressPropositionSerializer
import io.horizen.account.utils.ForgerIdentifier
import io.horizen.proposition.{PublicKey25519PropositionSerializer, VrfPublicKeySerializer}
import sparkz.core.serialization.SparkzSerializer
import sparkz.util.serialization.{Reader, Writer}

object ForgerBlockCountersSerializer extends SparkzSerializer[Map[ForgerIdentifier, Long]] {

  private val addressSerializer: AddressPropositionSerializer = AddressPropositionSerializer.getSerializer
  private val signPubKeySerializer: PublicKey25519PropositionSerializer =
    PublicKey25519PropositionSerializer.getSerializer
  private val vrfPubKeySerializer: VrfPublicKeySerializer = VrfPublicKeySerializer.getSerializer
  final val SERIALIZATION_FORMAT_1_4_FLAG = -1

  override def serialize(forgerBlockCounters: Map[ForgerIdentifier, Long], w: Writer): Unit = {
    w.putInt(forgerBlockCounters.size)
    forgerBlockCounters.foreach {
      case (forgerIdentifier, counter) =>
        addressSerializer.serialize(forgerIdentifier.getAddress, w)
        if (forgerIdentifier.getForgerKeys.isDefined) {
          w.putLong(SERIALIZATION_FORMAT_1_4_FLAG) //flag to indicate new serialization format is used
          forgerIdentifier.getForgerKeys.foreach { keys =>
            signPubKeySerializer.serialize(keys.blockSignPublicKey, w)
            vrfPubKeySerializer.serialize(keys.vrfPublicKey, w)
          }
        }
        w.putLong(counter)
    }
  }

  override def parse(r: Reader): Map[ForgerIdentifier, Long] = {
    val length = r.getInt()
    (1 to length).map { _ =>
      val address = addressSerializer.parse(r)
      val counter = r.getLong()
      if (counter == SERIALIZATION_FORMAT_1_4_FLAG) {
        val blockSignPublicKey = signPubKeySerializer.parse(r)
        val vrfPublicKey = vrfPubKeySerializer.parse(r)
        val counter = r.getLong()
        (new ForgerIdentifier(address, Some(ForgerPublicKeys(blockSignPublicKey, vrfPublicKey))), counter)
      } else {
        (new ForgerIdentifier(address), counter)
      }
    }.toMap
  }

}
