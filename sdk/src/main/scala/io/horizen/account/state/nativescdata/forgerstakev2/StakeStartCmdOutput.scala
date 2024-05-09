package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.Int32
import org.web3j.abi.datatypes.{DynamicStruct, StaticStruct, Type}

import java.util

case class StakeStartCmdOutput(epoch: Int) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {
    val listOfParams: util.List[Type[_]] = new util.ArrayList()
    listOfParams.add(new Int32(epoch))
    new StaticStruct(listOfParams)
  }

  override def toString: String =
    "%s(epoch: %s)"
      .format(this.getClass.toString, epoch)
}

object StakeStartCmdOutputDecoder
    extends ABIDecoder[StakeStartCmdOutput]
    with MsgProcessorInputDecoder[StakeStartCmdOutput] {

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] = {
    org.web3j.abi.Utils.convert(
      util.Arrays.asList(
        new TypeReference[Int32]() {},
      ),
    )
  }

  override def createType(listOfParams: util.List[Type[_]]): StakeStartCmdOutput = {
    val epoch = listOfParams.get(0).asInstanceOf[Int32].getValue.intValueExact()
    StakeStartCmdOutput(epoch)
  }
}
