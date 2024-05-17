package io.horizen.account.state

import io.horizen.account.fixtures.ForgerAccountFixture.getPrivateKeySecp256k1
import io.horizen.account.utils.ForgerIdentifier
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.secret.PrivateKey25519Creator
import io.horizen.vrf.VrfGeneratedDataProvider
import org.junit.Assert.{assertEquals, fail}
import org.junit.Test

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import scala.util.{Failure, Success}

class McForgerPoolRewardsSerializerTest {

  @Test
  def serializationRoundTripTest(): Unit = {
    val addr1 = getPrivateKeySecp256k1(1000).publicImage()
    val addr2 = getPrivateKeySecp256k1(1001).publicImage()
    val addr3 = getPrivateKeySecp256k1(1002).publicImage()
    val forgerBlockRewards = Map(
      new ForgerIdentifier(addr1) -> BigInteger.valueOf(1L),
      new ForgerIdentifier(addr2) -> BigInteger.valueOf(100L),
      new ForgerIdentifier(addr3) -> BigInteger.valueOf(9999999L),
    )

    val bytes = McForgerPoolRewardsSerializer.toBytes(forgerBlockRewards)

    McForgerPoolRewardsSerializer.parseBytesTry(bytes) match {
      case Failure(_)     => fail("Parsing failed in McForgerPoolRewardsSerializer")
      case Success(value) => assertEquals("Parsed value different from serialized value", value, forgerBlockRewards)
    }
  }

  @Test
  def serializationRoundTripTest_Empty(): Unit = {
    val forgerBlockRewards = Map.empty[ForgerIdentifier, BigInteger]

    val bytes = McForgerPoolRewardsSerializer.toBytes(forgerBlockRewards)

    McForgerPoolRewardsSerializer.parseBytesTry(bytes) match {
      case Failure(_)     => fail("Parsing failed in McForgerPoolRewardsSerializer")
      case Success(value) => assertEquals("Parsed value different from serialized value", value, forgerBlockRewards)
    }
  }

  @Test
  def serializationRoundTripTest_NewFormat(): Unit = {
    val addr1 = getPrivateKeySecp256k1(1000).publicImage()
    val proposition1: PublicKey25519Proposition =
      PrivateKey25519Creator.getInstance().generateSecret("test1".getBytes(StandardCharsets.UTF_8)).publicImage()
    val vrfPublicKey1: VrfPublicKey = VrfGeneratedDataProvider.getVrfSecretKey(1).publicImage()
    val addr2 = getPrivateKeySecp256k1(1001).publicImage()
    val proposition2: PublicKey25519Proposition =
      PrivateKey25519Creator.getInstance().generateSecret("test2".getBytes(StandardCharsets.UTF_8)).publicImage()
    val vrfPublicKey2: VrfPublicKey = VrfGeneratedDataProvider.getVrfSecretKey(2).publicImage()
    val addr3 = getPrivateKeySecp256k1(1002).publicImage()
    val proposition3: PublicKey25519Proposition =
      PrivateKey25519Creator.getInstance().generateSecret("test3".getBytes(StandardCharsets.UTF_8)).publicImage()
    val vrfPublicKey3: VrfPublicKey = VrfGeneratedDataProvider.getVrfSecretKey(3).publicImage()
    val forgerBlockRewards = Map(
      new ForgerIdentifier(addr1, Some(ForgerPublicKeys(proposition1, vrfPublicKey1)))-> BigInteger.valueOf(1L),
      new ForgerIdentifier(addr2, Some(ForgerPublicKeys(proposition2, vrfPublicKey2))) -> BigInteger.valueOf(100L),
      new ForgerIdentifier(addr3, Some(ForgerPublicKeys(proposition3, vrfPublicKey3)))  -> BigInteger.valueOf(9999999L),
    )

    val bytes = McForgerPoolRewardsSerializer.toBytes(forgerBlockRewards)

    McForgerPoolRewardsSerializer.parseBytesTry(bytes) match {
      case Failure(_)     => fail("Parsing failed in McForgerPoolRewardsSerializer")
      case Success(value) => assertEquals("Parsed value different from serialized value", value, forgerBlockRewards)
    }
  }

}
