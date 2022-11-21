package com.horizen.account.transaction;

import com.horizen.account.fixtures.EthereumTransactionFixture;
import com.horizen.account.state.GasUtil;
import com.horizen.transaction.TransactionSerializer;
import com.horizen.utils.BytesUtils;
import org.junit.Test;
import org.web3j.crypto.ECKeyPair;
import scala.Option;
import scala.util.Try;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;

import static org.junit.Assert.*;

public class EthereumTransactionSerializerTest implements EthereumTransactionFixture {

    // Check that using the same key pair for signing two transactions give the same from address
    @Test
    public void checkSigningTxTest() {

        var privKey = new BigInteger("49128115046059273042656529250771669375541382406576940612305697909438063650480");
        var pubKey = new BigInteger("8198110339830204259458045104072783158824826560452916203793316544691619725076836725487148486981196842344156645049311437356787993166435716250962254331877695");
        var account1KeyPair = Option.apply(new ECKeyPair(privKey, pubKey));

        var nonce = BigInteger.valueOf(0);
        var value = BigInteger.valueOf(11);
        var gasPrice = BigInteger.valueOf(12);
        var gasLimit = GasUtil.TxGas();

        var tx1 = createLegacyTransaction(value, nonce, account1KeyPair, gasPrice, gasLimit);

        try {
            tx1.semanticValidity();
        } catch (Throwable t) {
            fail("Expected a valid tx: " + t.getMessage());
        }

        var tx2 = createLegacyTransaction(value, nonce.add(BigInteger.ONE), account1KeyPair, gasPrice, gasLimit);

        try {
            tx2.semanticValidity();
        } catch (Throwable t) {
            fail("Expected a valid tx: " + t.getMessage());
        }

        // different signatures but same from address
        assertNotEquals(tx1.getSignature(), tx2.getSignature());
        assertEquals(tx1.getFrom(), tx2.getFrom());

        var maxFeePerGas = BigInteger.valueOf(15);
        var maxPriorityFeePerGas = BigInteger.valueOf(15);
        var tx3 = createEIP1559Transaction(value, nonce.add(BigInteger.ONE), account1KeyPair, maxFeePerGas, maxPriorityFeePerGas, gasLimit);

        try {
            tx3.semanticValidity();
        } catch (Throwable t) {
            fail("Expected a valid tx: " + t.getMessage());
        }

        // different signatures but same from address
        assertNotEquals(tx1.getSignature(), tx3.getSignature());
        assertEquals(tx1.getFrom(), tx3.getFrom());

        var tx4 = createLegacyEip155Transaction(value, nonce.add(BigInteger.ONE), account1KeyPair, gasPrice, gasLimit);

        try {
            tx4.semanticValidity();
        } catch (Throwable t) {
            fail("Expected a valid tx: " + t.getMessage());
        }

        // different signatures but same from address
        assertNotEquals(tx1.getSignature(), tx4.getSignature());
        assertEquals(tx1.getFrom(), tx4.getFrom());
    }

    @Test
    public void regressionTestLegacySigned() {
        EthereumTransaction transaction = getEoa2EoaLegacyTransaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_legacy_signed_hex", false);
    }

    @Test
    public void regressionTestLegacyUnsigned() {
        EthereumTransaction transaction = getUnsignedEoa2EoaLegacyTransaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_legacy_unsigned_hex", false);
    }

    @Test
    public void regressionTestEoa2EoaEip1559() {
        EthereumTransaction transaction = getEoa2EoaEip1559Transaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_eip1559_signed_hex", false);
    }

    @Test
    public void regressionTestEoa2EoaEip1559Unsigned() {
        EthereumTransaction transaction = getUnsignedEoa2EoaEip1559Transaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_eip1559_unsigned_hex", false);
    }

    @Test
    public void regressionTestEip155() {
        EthereumTransaction transaction = getEoa2EoaEip155LegacyTransaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_eip155_legacy_signed_hex", false);
    }

    @Test
    public void regressionTestUnsignedEip155() {
        EthereumTransaction transaction = getUnsignedEip155LegacyTransaction();
        doTest(transaction, "ethereumtransaction_eoa2eoa_eip155_legacy_unsigned_hex", false);
    }

    @Test
    public void regressionTestContractDeploymentEip1559() {
        EthereumTransaction transaction = getContractDeploymentEip1559Transaction();
        doTest(transaction, "ethereumtransaction_contract_deployment_eip1559_hex", false);
    }

    @Test
    public void regressionTestContractCallEip155Legacy() {
        EthereumTransaction transaction = getContractCallEip155LegacyTransaction();
        doTest(transaction, "ethereumtransaction_contract_call_eip155_legacy_hex", false);
    }

    private void doTest(EthereumTransaction transaction, String hexFileName, boolean writeMode) {
        // Set `true` and run if you want to update regression data.
        if (writeMode) {
            try {
                BufferedWriter out = new BufferedWriter(new FileWriter("src/test/resources/" +
                        hexFileName));
                out.write(BytesUtils.toHexString(transaction.bytes()));
                out.close();
            } catch (Throwable e) {
                fail(e.toString());
                return;
            }
        }

        byte[] bytes;
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            FileReader file = new FileReader(classLoader.getResource(hexFileName).getFile());
            bytes = BytesUtils.fromHexString(new BufferedReader(file).readLine());
        }
        catch (Exception e) {
            fail(e.toString());
            return;
        }

        TransactionSerializer serializer = transaction.serializer();
        Try<EthereumTransaction> t = serializer.parseBytesTry(bytes);
        assertTrue("Transaction serialization failed.", t.isSuccess());

        EthereumTransaction parsedTransaction = t.get();
        System.out.println(transaction.id());
        System.out.println(parsedTransaction.id());
        assertEquals("Transaction is different to the origin.", transaction.id(), parsedTransaction.id());
    }
}
