package io.horizen.account.state

import io.horizen.evm.Address
import io.horizen.fixtures.SecretFixture
import org.junit.Assert.{assertArrayEquals, assertEquals, assertFalse, assertTrue}
import org.junit.Test
import org.mockito.{ArgumentMatchers, Mockito}
import org.scalatestplus.junit.JUnitSuite
import org.scalatestplus.mockito.MockitoSugar

import java.math.BigInteger

class EoaMessageProcessorTest extends JUnitSuite with MockitoSugar with SecretFixture with MessageProcessorFixture {

  @Test
  def init(): Unit = {
    val mockStateView: AccountStateView = mock[AccountStateView]

    try {
      EoaMessageProcessor.init(mockStateView, 0)
    } catch {
      case ex: Exception =>
        fail("Initialization failed", ex)
    }
  }

  @Test
  def testCanProcess(): Unit = {
    val address = randomAddress
    val value = BigInteger.ONE
    val msg = getMessage(address, value, Array.emptyByteArray)

    val mockStateView = mock[AccountStateView]

    // Test 1: send to EOA account, tx with empty "data"
    Mockito
      .when(mockStateView.isEoaAccount(ArgumentMatchers.any[Address]))
      .thenAnswer(args => {
        assertEquals("Different address found", msg.getTo.get(), args.getArgument(0))
        true
      })
    assertTrue(
      "Message for EoaMessageProcessor cannot be processed",
      TestContext.canProcess(EoaMessageProcessor, msg, mockStateView, 0)
    )

    // Test 2: send to EOA account, tx with no-empty "data"
    val data = new Array[Byte](1000)
    val msgWithData = getMessage(address, value, data)
    assertTrue(
      "Message for EoaMessageProcessor cannot be processed",
      TestContext.canProcess(EoaMessageProcessor, msgWithData, mockStateView, 0)
    )

    // Test 3: Failure: send to smart contract account
    Mockito.reset(mockStateView)
    Mockito
      .when(mockStateView.isEoaAccount(ArgumentMatchers.any[Address]))
      .thenAnswer(args => {
        assertEquals("Different address found", msg.getTo.get(), args.getArgument(0))
        false
      })
    assertFalse(
      "Message for EoaMessageProcessor wrongly can be processed",
      TestContext.canProcess(EoaMessageProcessor, msg, mockStateView, 0)
    )

    // Test 4: Failure: to is null
    Mockito.reset(mockStateView)
    val contractDeclarationMessage = getMessage(null, value, data)
    assertFalse(
      "Message for EoaMessageProcessor wrongly can be processed",
      TestContext.canProcess(EoaMessageProcessor, contractDeclarationMessage, mockStateView, 0)
    )

    // Test 4: Failure: data is empty array
    Mockito.reset(mockStateView)
    val contractDeclarationMessage2 = getMessage(null, value, Array.emptyByteArray)
    assertFalse(
      "Message for EoaMessageProcessor wrongly can be processed",
      TestContext.canProcess(EoaMessageProcessor, contractDeclarationMessage2, mockStateView, 0)
    )
  }

  @Test
  def process(): Unit = {
    val msg = getMessage(randomAddress, randomU256)
    val mockStateView = mock[AccountStateView]

    // Test 1: Success: no failures during balance changes
    Mockito
      .when(mockStateView.subBalance(ArgumentMatchers.any[Address], ArgumentMatchers.any[BigInteger]))
      .thenAnswer(args => {
        assertEquals("Different address found", msg.getFrom, args.getArgument(0))
        assertEquals("Different amount found", msg.getValue, args.getArgument(1))
      })

    Mockito
      .when(mockStateView.addBalance(ArgumentMatchers.any[Address], ArgumentMatchers.any[BigInteger]))
      .thenAnswer(args => {
        assertEquals("Different address found", msg.getTo.get(), args.getArgument(0))
        assertEquals("Different amount found", msg.getValue, args.getArgument(1))
      })

    val returnData = assertGas(0, msg, mockStateView, EoaMessageProcessor, defaultBlockContext)
    assertArrayEquals("Different return data found", Array.emptyByteArray, returnData)

    // Test 2: Failure during subBalance
    Mockito.reset(mockStateView)
    Mockito
      .when(mockStateView.subBalance(ArgumentMatchers.any[Address], ArgumentMatchers.any[BigInteger]))
      .thenThrow(new ExecutionFailedException("something went error"))
    assertThrows[ExecutionFailedException](
      withGas(TestContext.process(EoaMessageProcessor, msg, mockStateView, defaultBlockContext, _, mockStateView))
    )

    // Test 3: Failure during addBalance
    Mockito.reset(mockStateView)
    Mockito
      .when(mockStateView.addBalance(ArgumentMatchers.any[Address], ArgumentMatchers.any[BigInteger]))
      .thenThrow(new ExecutionFailedException("something went error"))
    assertThrows[ExecutionFailedException](
      withGas(TestContext.process(EoaMessageProcessor, msg, mockStateView, defaultBlockContext, _, mockStateView))
    )
  }
}
