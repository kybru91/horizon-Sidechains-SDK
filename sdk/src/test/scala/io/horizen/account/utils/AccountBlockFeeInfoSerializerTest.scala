package io.horizen.account.utils

import io.horizen.account.proposition.AddressProposition
import io.horizen.account.state.ForgerPublicKeys
import io.horizen.fixtures.SecretFixture
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.secret.PrivateKey25519Creator
import io.horizen.vrf.VrfGeneratedDataProvider
import org.junit.Assert.assertEquals
import org.junit.Test

import java.math.BigInteger
import java.nio.charset.StandardCharsets

class AccountBlockFeeInfoSerializerTest extends SecretFixture {
  @Test
  def serializeAccountBlockFeeInfo(): Unit = {
    val address: AddressProposition = getAddressProposition(123)
    val baseFee: BigInteger = BigInteger.valueOf(1234567890L)
    val forgerTips: BigInteger = BigInteger.valueOf(1234567890L)
    val feeInto: AccountBlockFeeInfo = AccountBlockFeeInfo(baseFee, forgerTips, address)

    val serializedBytes: Array[Byte] = AccountBlockFeeInfoSerializer.toBytes(feeInto)

    val deserializedFeeInto: AccountBlockFeeInfo = AccountBlockFeeInfoSerializer.parseBytes(serializedBytes)

    assertEquals(feeInto, deserializedFeeInto)
  }

  @Test
  def serializeAccountBlockFeeInfoNewFormat(): Unit = {
    val address: AddressProposition = getAddressProposition(123)
    val proposition: PublicKey25519Proposition = PrivateKey25519Creator.getInstance().generateSecret("test1".getBytes(StandardCharsets.UTF_8)).publicImage()
    val vrfPublicKey: VrfPublicKey = VrfGeneratedDataProvider.getVrfSecretKey(1).publicImage()
    val baseFee: BigInteger = BigInteger.valueOf(1234567890L)
    val forgerTips: BigInteger = BigInteger.valueOf(1234567890L)
    val feeInto: AccountBlockFeeInfo = AccountBlockFeeInfo(baseFee, forgerTips, address, Some(ForgerPublicKeys(proposition, vrfPublicKey)))

    val serializedBytes: Array[Byte] = AccountBlockFeeInfoSerializer.toBytes(feeInto)

    val deserializedFeeInto: AccountBlockFeeInfo = AccountBlockFeeInfoSerializer.parseBytes(serializedBytes)

    assertEquals(feeInto, deserializedFeeInto)
  }
}
