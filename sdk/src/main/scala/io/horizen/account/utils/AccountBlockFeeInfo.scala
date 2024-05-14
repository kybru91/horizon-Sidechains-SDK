package io.horizen.account.utils

import com.fasterxml.jackson.annotation.JsonView
import io.horizen.account.proposition.{AddressProposition, AddressPropositionSerializer}
import io.horizen.json.Views
import io.horizen.proposition.{PublicKey25519Proposition, PublicKey25519PropositionSerializer, VrfPublicKey, VrfPublicKeySerializer}
import sparkz.core.serialization.{BytesSerializable, SparkzSerializer}
import sparkz.util.serialization.{Reader, Writer}

import java.math.BigInteger

@JsonView(Array(classOf[Views.Default]))
case class AccountBlockFeeInfo(
  baseFee: BigInteger,
  forgerTips: BigInteger,
  forgerAddress: AddressProposition,
  blockSignPublicKey: Option[PublicKey25519Proposition] = None,
  vrfPublicKey: Option[VrfPublicKey] = None,
) extends BytesSerializable {
  override type M = AccountBlockFeeInfo
  override def serializer: SparkzSerializer[AccountBlockFeeInfo] = AccountBlockFeeInfoSerializer
}

object AccountBlockFeeInfoSerializer extends SparkzSerializer[AccountBlockFeeInfo] {
  override def serialize(obj: AccountBlockFeeInfo, w: Writer): Unit = {
    val baseFeeByteArray = obj.baseFee.toByteArray
    w.putInt(baseFeeByteArray.length)
    w.putBytes(baseFeeByteArray)
    val forgerTipsByteArray = obj.forgerTips.toByteArray
    w.putInt(forgerTipsByteArray.length)
    w.putBytes(forgerTipsByteArray)
    AddressPropositionSerializer.getSerializer.serialize(obj.forgerAddress, w)
    obj.blockSignPublicKey.foreach(p => PublicKey25519PropositionSerializer.getSerializer.serialize(p, w))
    obj.vrfPublicKey.foreach(p => VrfPublicKeySerializer.getSerializer.serialize(p, w))
  }

  override def parse(r: Reader): AccountBlockFeeInfo = {
    val baseFeeLength = r.getInt()
    val baseFee = new BigIntegerUInt256(r.getBytes(baseFeeLength)).getBigInt

    val forgerTipsLength = r.getInt()
    val forgerTips = new BigIntegerUInt256(r.getBytes(forgerTipsLength)).getBigInt

    val forgerRewardKey: AddressProposition = AddressPropositionSerializer.getSerializer.parse(r)
    r.remaining match {
      case 0 => AccountBlockFeeInfo(baseFee, forgerTips, forgerRewardKey)
      case _ =>
        val blockSignPublicKey = PublicKey25519PropositionSerializer.getSerializer.parse(r)
        val vrfPublicKey = VrfPublicKeySerializer.getSerializer.parse(r)
        AccountBlockFeeInfo(baseFee, forgerTips, forgerRewardKey, Some(blockSignPublicKey), Some(vrfPublicKey))
    }
  }
}
