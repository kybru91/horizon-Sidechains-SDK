package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.Int32
import org.web3j.abi.datatypes.{StaticStruct, Type}

import java.util

object PagedForgersCmdInputDecoder
  extends ABIDecoder[PagedForgersCmdInput]
    with MsgProcessorInputDecoder[PagedForgersCmdInput]
    with VRFDecoder{

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] =
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Int32]() {},
      new TypeReference[Int32]() {}
    ))

  override def createType(listOfParams: util.List[Type[_]]): PagedForgersCmdInput = {
    val startIndex = listOfParams.get(0).asInstanceOf[Int32].getValue.intValueExact()
    val pageSize = listOfParams.get(1).asInstanceOf[Int32].getValue.intValueExact()
    PagedForgersCmdInput(startIndex, pageSize)
  }

}

case class PagedForgersCmdInput(startIndex: Int, pageSize: Int) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {

    val listOfParams: util.List[Type[_]] = util.Arrays.asList(
      new Int32(startIndex),
      new Int32(pageSize))

    new StaticStruct(listOfParams)
  }

  override def toString: String = "%s(startIndex: %s, pageSize: %s)"
    .format(this.getClass.toString, startIndex, pageSize)
}
