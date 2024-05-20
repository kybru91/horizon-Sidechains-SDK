package io.horizen.account.utils

import com.fasterxml.jackson.annotation.JsonView
import io.horizen.account.proposition.{AddressProposition, AddressPropositionSerializer}
import io.horizen.json.Views
import sparkz.util.serialization.{Reader, Writer}
import sparkz.core.serialization.{BytesSerializable, SparkzSerializer}

import java.math.BigInteger

@JsonView(Array(classOf[Views.Default]))
case class AccountPayment(address: AddressProposition,
                          value: BigInteger,
                          valueFromMainchain: Option[BigInteger] = None,
                          valueFromFees: Option[BigInteger] = None) extends BytesSerializable {
  override type M = AccountPayment

  override def serializer: SparkzSerializer[AccountPayment] = AccountPaymentSerializer
}

object AccountPaymentSerializer extends SparkzSerializer[AccountPayment] {
  final val SERIALIZATION_FORMAT_1_4_FLAG = -1

  override def serialize(obj: AccountPayment, w: Writer): Unit = {
    AddressPropositionSerializer.getSerializer.serialize(obj.address, w)
    // porkaround to support old and new serialization format in parallel
    if (obj.valueFromMainchain.isDefined && obj.valueFromFees.isDefined) {
      w.putInt(SERIALIZATION_FORMAT_1_4_FLAG) //flag to indicate new serialization format is used
      w.putInt(obj.value.toByteArray.length)
      w.putBytes(obj.value.toByteArray)
      w.putInt(obj.valueFromMainchain.get.toByteArray.length)
      w.putBytes(obj.valueFromMainchain.get.toByteArray)
      w.putInt(obj.valueFromFees.get.toByteArray.length)
      w.putBytes(obj.valueFromFees.get.toByteArray)
    } else {
      w.putInt(obj.value.toByteArray.length)
      w.putBytes(obj.value.toByteArray)
    }
  }

  override def parse(r: Reader): AccountPayment = {
    val address = AddressPropositionSerializer.getSerializer.parse(r)
    val valueLength = r.getInt
    if (valueLength == SERIALIZATION_FORMAT_1_4_FLAG) {
      val valueLength = r.getInt
      val value = new BigIntegerUInt256(r.getBytes(valueLength)).getBigInt
      val valueFromMainchainLength = r.getInt
      val valueFromMainchain = new BigIntegerUInt256(r.getBytes(valueFromMainchainLength)).getBigInt
      val valueFromFeesLength = r.getInt
      val valueFromFees = new BigIntegerUInt256(r.getBytes(valueFromFeesLength)).getBigInt
      AccountPayment(address, value, Some(valueFromMainchain), Some(valueFromFees))
    } else {
      val value = new BigIntegerUInt256(r.getBytes(valueLength)).getBigInt
      AccountPayment(address, value, None, None)
    }
  }
}

