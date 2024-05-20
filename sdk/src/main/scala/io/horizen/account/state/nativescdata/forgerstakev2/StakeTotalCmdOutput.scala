package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.abi.datatypes.{DynamicArray, DynamicStruct, Type}

import java.math.BigInteger
import java.util
import scala.collection.JavaConverters
import scala.jdk.CollectionConverters.asScalaBufferConverter


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

object StakeTotalCmdOutputDecoder
  extends ABIDecoder[StakeTotalCmdOutput]
    with MsgProcessorInputDecoder[StakeTotalCmdOutput] {

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] = {
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[DynamicArray[Uint256]]() {}))
  }

  override def createType(listOfParams: util.List[Type[_]]): StakeTotalCmdOutput = {
    val listOfStakes = listOfParams.get(0).asInstanceOf[DynamicArray[Uint256]].getValue
    StakeTotalCmdOutput(listOfStakes.asScala.map(_.getValue))
  }
}