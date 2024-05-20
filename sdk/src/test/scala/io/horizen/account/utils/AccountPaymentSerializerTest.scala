package io.horizen.account.utils

import io.horizen.account.proposition.AddressProposition
import io.horizen.fixtures.SecretFixture
import org.junit.Assert.assertEquals
import org.junit.Test

import java.math.BigInteger

class AccountPaymentSerializerTest extends SecretFixture  {
  @Test
  def serializeAccountPayment(): Unit = {
    val address: AddressProposition = getAddressProposition(123)
    val value: BigInteger = BigInteger.valueOf(1234567890L)
    val accountPayment: AccountPayment = AccountPayment(address, value)

    val serializedBytes: Array[Byte] = AccountPaymentSerializer.toBytes(accountPayment)

    val deserializedAccountPayment: AccountPayment = AccountPaymentSerializer.parseBytes(serializedBytes)

    assertEquals(accountPayment, deserializedAccountPayment)
  }

  @Test
  def serializeAccountPaymentNewFormat(): Unit = {
    val address: AddressProposition = getAddressProposition(123)
    val value: BigInteger = BigInteger.valueOf(1234567890L)
    val valueFromMainchain: BigInteger = BigInteger.valueOf(2222222222L)
    val valueFromFees: BigInteger = BigInteger.valueOf(5555555555L)
    val accountPayment: AccountPayment = AccountPayment(address, value, Some(valueFromMainchain), Some(valueFromFees))

    val serializedBytes: Array[Byte] = AccountPaymentSerializer.toBytes(accountPayment)

    val deserializedAccountPayment: AccountPayment = AccountPaymentSerializer.parseBytes(serializedBytes)

    assertEquals(accountPayment, deserializedAccountPayment)
  }
}
