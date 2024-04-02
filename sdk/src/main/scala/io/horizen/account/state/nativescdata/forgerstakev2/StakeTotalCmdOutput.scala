package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.ABIEncodable
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.abi.datatypes.{DynamicArray, DynamicStruct, Type}

import java.math.BigInteger
import java.util
import scala.collection.JavaConverters


case class StakeTotalCmdOutput(listOfStakes: Seq[BigInteger]) extends ABIEncodable[DynamicStruct] {

  override def asABIType(): DynamicStruct = {
    val seqOfStruct = listOfStakes.map(new Uint256(_))
    val listOfStruct = JavaConverters.seqAsJavaList(seqOfStruct)
    val theType = classOf[Uint256]
    val listOfParams: util.List[Type[_]] = util.Arrays.asList(
      new DynamicArray(theType, listOfStruct)
    )
    new DynamicStruct(listOfParams)
  }

  override def toString: String = "%s(listOfStakes: %s)"
    .format(this.getClass.toString, listOfStakes)
}
