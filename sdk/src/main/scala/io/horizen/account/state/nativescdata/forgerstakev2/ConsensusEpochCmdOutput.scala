package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.abi.{ABIDecoder, ABIEncodable, MsgProcessorInputDecoder}
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.generated.{Uint256, Uint32}
import org.web3j.abi.datatypes.{DynamicArray, DynamicStruct, StaticStruct, Type}

import java.util
import scala.jdk.CollectionConverters.asScalaBufferConverter


case class ConsensusEpochCmdOutput(epoch: Int) extends ABIEncodable[StaticStruct] {

  override def asABIType(): StaticStruct = {

    val listOfParams: util.List[Type[_]] = util.Arrays.asList(
      new Uint32(epoch)
    )
    new StaticStruct(listOfParams)
  }

  override def toString: String = "%s(epoch: %s)"
    .format(this.getClass.toString, epoch)
}

object ConsensusEpochCmdOutputDecoder
  extends ABIDecoder[ConsensusEpochCmdOutput]
    with MsgProcessorInputDecoder[ConsensusEpochCmdOutput] {

  override val getListOfABIParamTypes: util.List[TypeReference[Type[_]]] = {
    org.web3j.abi.Utils.convert(util.Arrays.asList(
      new TypeReference[Uint32]() {}))
  }

  override def createType(listOfParams: util.List[Type[_]]): ConsensusEpochCmdOutput = {
    val epoch = listOfParams.get(0).asInstanceOf[Uint32].getValue
    ConsensusEpochCmdOutput(epoch.intValueExact())
  }
}