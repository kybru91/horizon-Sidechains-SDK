package com.horizen.account.transaction;

import com.fasterxml.jackson.annotation.*;
import com.horizen.account.proof.SignatureSecp256k1;
import com.horizen.account.proposition.AddressProposition;
import com.horizen.account.state.GasUintOverflowException;
import com.horizen.account.state.GasUtil;
import com.horizen.account.state.Message;
import com.horizen.account.utils.Account;
import com.horizen.account.utils.BigIntegerUtil;
import com.horizen.account.utils.EthereumTransactionUtils;
import com.horizen.serialization.Views;
import com.horizen.transaction.TransactionSerializer;
import com.horizen.transaction.exception.TransactionSemanticValidityException;
import com.horizen.utils.BytesUtils;
import org.jetbrains.annotations.NotNull;
import org.web3j.crypto.*;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.crypto.transaction.type.LegacyTransaction;
import org.web3j.crypto.transaction.type.Transaction1559;
import org.web3j.crypto.transaction.type.TransactionType;
import org.web3j.utils.Numeric;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Objects;

@JsonPropertyOrder({
        "id", "from", "to", "value", "nonce", "data",
        "gasPrice", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas",
        "eip1559", "type", "chainId", "signed", "signature"
})
@JsonIgnoreProperties({"transaction", "encoder", "modifierTypeId"})
@JsonView(Views.Default.class)
public class EthereumTransaction extends AccountTransaction<AddressProposition, SignatureSecp256k1> {

    private final RawTransaction transaction;

    // depends on the transaction
    public EthereumTransaction(
            RawTransaction transaction
    ) throws NullPointerException {
        Objects.requireNonNull(transaction, "RawTransaction private data member is null!");
        if (transaction instanceof SignedRawTransaction)
            Objects.requireNonNull(((SignedRawTransaction) transaction).getSignatureData(), "signature data can not be null in a signed transaction!");
        this.transaction = transaction;
    }

    // creates a legacy transaction
    public EthereumTransaction(
            @Nullable String to,
            @NotNull BigInteger nonce,
            @NotNull BigInteger gasPrice,
            @NotNull BigInteger gasLimit,
            @Nullable BigInteger value,
            @Nullable String data,
            @Nullable SignatureData signature
    ) {
        this(signature != null ?
                new SignedRawTransaction(
                        RawTransaction.createTransaction(
                                nonce,
                                gasPrice,
                                gasLimit,
                                to != null ? to : "",
                                value != null ? value :
                                        BigInteger.ZERO,
                                data
                        ).getTransaction(),
                        signature) :
                RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, data)
        );
    }

    private static boolean checkSignatureData(SignatureData signature) {
        return SignatureSecp256k1.checkSignatureDataSizes(
                signature.getV(), signature.getR(), signature.getS());
    }

    // creates an eip1559 transaction
    public EthereumTransaction(
            long chainId,
            @Nullable String to,
            @NotNull BigInteger nonce,
            @NotNull BigInteger gasLimit,
            @NotNull BigInteger maxPriorityFeePerGas,
            @NotNull BigInteger maxFeePerGas,
            @Nullable BigInteger value,
            @Nullable String data,
            @Nullable SignatureData signature
    ) {
        this(
                signature != null ?
                        new SignedRawTransaction(
                                RawTransaction.createTransaction(chainId, nonce, gasLimit, to != null ? to : "", value != null ? value :
                                        BigInteger.ZERO, data, maxPriorityFeePerGas, maxFeePerGas).getTransaction(), signature)
                        : RawTransaction.createTransaction(chainId, nonce, gasLimit, to != null ? to : "", value != null ? value :
                        BigInteger.ZERO, data, maxPriorityFeePerGas, maxFeePerGas)
        );
    }

    public RawTransaction getTransaction() {
        return this.transaction;
    }

    public boolean isSigned() {
        return this.transaction instanceof SignedRawTransaction;
    }

    @Override
    public byte transactionTypeId() {
        return AccountTransactionsIdsEnum.EthereumTransactionId.id();
    }

    @Override
    @JsonProperty("id")
    public String id() {
        byte[] encodedMessage;
        if (this.isSigned()) {
            SignedRawTransaction stx = (SignedRawTransaction) this.transaction;
            encodedMessage = TransactionEncoder.encode(this.getTransaction(),
                    stx.getSignatureData());
        } else encodedMessage = TransactionEncoder.encode(this.getTransaction());
        return BytesUtils.toHexString(Hash.sha3(encodedMessage, 0, encodedMessage.length));
    }

    @Override
    @JsonProperty("type")
    public byte version() {
        if (transaction.getType() == TransactionType.LEGACY)
            return 0x0;
        return transaction.getType().getRlpType();
    }

    @Override
    public TransactionSerializer serializer() {
        return EthereumTransactionSerializer.getSerializer();
    }

    @Override
    public void semanticValidity() throws TransactionSemanticValidityException {
        if (getFrom() == null)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is not properly signed, " +
                    "can not get valid from address", id()));
        if (getToAddress() != null && getToAddress().length() != 0 &&
                Numeric.hexStringToByteArray(getToAddress()).length != Account.ADDRESS_SIZE) {
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "invalid to address", id()));
        }
        if (getTo() == null && getData().length == 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "smart contract declaration transaction without data", id()));
        if (getValue().signum() < 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "negative value", id()));
        if (getNonce().signum() < 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "negative nonce", id()));
        if (getGasLimit().signum() <= 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "non-positive gas limit", id()));
        if (!BigIntegerUtil.isUint64(getGasLimit()))
            throw new GasUintOverflowException();
        if (getMaxFeePerGas().signum() < 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "eip1559 transaction with negative maxFeePerGas", id()));
        if (getMaxPriorityFeePerGas().signum() < 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "eip1559 transaction with negative maxPriorityFeePerGas", id()));
        if (getMaxFeePerGas().bitLength() > 256)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "eip1559 transaction maxFeePerGas bit length [%d] is too high", id(), getMaxFeePerGas().bitLength()));
        if (getMaxPriorityFeePerGas().bitLength() > 256)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "eip1559 transaction maxPriorityFeePerGas bit length [%d] is too high", id(), getMaxPriorityFeePerGas().bitLength()));
        if (getMaxFeePerGas().compareTo(getMaxPriorityFeePerGas()) < 0)
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                            "eip1559 transaction max priority fee per gas [%s] higher than max fee per gas [%s]",
                    id(), getMaxPriorityFeePerGas(), getMaxFeePerGas()));
        if (getGasLimit().compareTo(GasUtil.intrinsicGas(getData(), getTo() == null)) < 0) {
            throw new TransactionSemanticValidityException(String.format("Transaction [%s] is semantically invalid: " +
                    "gas limit is below intrinsic gas", id()));
        }
        if (!this.getSignature().isValid(this.getFrom(), this.messageToSign()))
            throw new TransactionSemanticValidityException("Cannot create signed transaction with invalid " +
                    "signature");

    }

    @Override
    public long size() {
        return serializer().toBytes(this).length;
    }

    @Override
    public BigInteger getNonce() {
        return this.transaction.getNonce();
    }

    @Override
    public BigInteger getGasPrice() {
        if (!this.isEIP1559())
            return this.legacyTx().getGasPrice();
        //in Geth for EIP1559 tx gasPrice returns gasFeeCap
        return getMaxFeePerGas();
    }

    @Override
    public BigInteger getMaxFeePerGas() {
        if (this.isEIP1559())
            return this.eip1559Tx().getMaxFeePerGas();
        else
            //in Geth for Legacy tx gasFeeCap is equal to gasPrice
            return this.legacyTx().getGasPrice();
    }

    public BigInteger getMaxPriorityFeePerGas() {
        if (this.isEIP1559())
            return this.eip1559Tx().getMaxPriorityFeePerGas();
        else
            //in Geth for Legacy tx MaxPriorityFee is equal to gasPrice
            return this.legacyTx().getGasPrice();
    }

    public Long getChainId() {
        if (this.isEIP1559())
            return this.eip1559Tx().getChainId();
        else if (this.isSigned()) {
            var signedTx = (SignedRawTransaction) this.transaction;
            var sigData = signedTx.getSignatureData();
            if (sigData.getS()[0] == 0 && sigData.getR()[0] == 0 && sigData.getS().length == 1 && sigData.getR().length == 1) {
                // for a not-really signed legacy tx implementing EIP155, here the chainid is the V itself
                // the caller needs it for encoding the tx properly
                return EthereumTransactionUtils.convertToLong(sigData.getV());
            } else {
                // for a fully signed legacy tx implementing EIP155
                return ((SignedRawTransaction) this.transaction).getChainId();
            }
        }

        return null;
    }

    public boolean isEIP1559() {
        return this.transaction.getTransaction() instanceof Transaction1559;
    }

    private Transaction1559 eip1559Tx() {
        return (Transaction1559) this.transaction.getTransaction();
    }

    private LegacyTransaction legacyTx() {
        return (LegacyTransaction) this.transaction.getTransaction();
    }

    @Override
    public BigInteger getGasLimit() {
        return this.transaction.getGasLimit();
    }

    @Override
    public AddressProposition getFrom() {
        if (this.isSigned() && checkSignatureData(getSignatureData()))
            return new AddressProposition(Numeric.hexStringToByteArray(getFromAddress()));
        return null;
    }

    @Override
    public AddressProposition getTo() {
        String address = getToAddress();
        // In case of smart contract declaration
        if (address == null)
            return null;

        // TODO: do we really need the checks below? can we have address of different length? Add more UTs for this tx type.
        // TODO: proabaly we need more checks in semantic validity method
        var to = Numeric.hexStringToByteArray(address);
        if (to.length == 0)
            return null;

        if (to.length == Account.ADDRESS_SIZE)
            return new AddressProposition(to);

        throw new RuntimeException(String.format("Invalid to address length %d", to.length));
    }

    @JsonIgnore
    public String getToAddress() {
        return this.transaction.getTo();
    }

    @JsonIgnore
    public String getFromAddress() {
        if (this.isSigned() && checkSignatureData(getSignatureData())) try {
            return ((SignedRawTransaction) this.transaction).getFrom();
        } catch (SignatureException ignored) {
        }
        return "";
    }

    @Override
    public BigInteger getValue() {
        return this.transaction.getValue();
    }

    @Override
    public byte[] getData() {
        return Numeric.hexStringToByteArray(transaction.getData());
    }

    @Override
    public SignatureSecp256k1 getSignature() {
        if (this.isSigned() && checkSignatureData(getSignatureData())) {
            SignedRawTransaction stx = (SignedRawTransaction) this.transaction;
            return new SignatureSecp256k1(
                    new byte[]{stx.getRealV(Numeric.toBigInt(stx.getSignatureData().getV()))},
                    stx.getSignatureData().getR(),
                    stx.getSignatureData().getS());
        }
        return null;
    }


    @JsonIgnore
    public Sign.SignatureData getSignatureData() {
        if (this.isSigned()) {
            SignedRawTransaction stx = (SignedRawTransaction) this.transaction;
            return new Sign.SignatureData(
                    stx.getSignatureData().getV(),
                    stx.getSignatureData().getR(),
                    stx.getSignatureData().getS());
        }
        return null;
    }

    // In case of EIP155 tx getV() returns the value carrying the chainId
    @JsonIgnore
    public byte[] getV() {
        return (getSignatureData() != null) ? getSignatureData().getV() : null;
    }

    @JsonIgnore
    public byte[] getR() {
        return (getSignatureData() != null) ? getSignatureData().getR() : null;
    }

    @JsonIgnore
    public byte[] getS() {
        return (getSignatureData() != null) ? getSignatureData().getS() : null;
    }

    @Override
    public String toString() {
        if (this.isEIP1559())
            return String.format(
                "EthereumTransaction{id=%s, from=%s, nonce=%s, gasLimit=%s, to=%s, value=%s, data=%s, " +
                        "maxFeePerGas=%s, maxPriorityFeePerGas=%s, Signature=%s}",
                id(),
                getFromAddress(),
                Numeric.toHexStringWithPrefix(this.getNonce() != null ? this.getNonce() : BigInteger.ZERO),
                Numeric.toHexStringWithPrefix(this.getGasLimit() != null ? this.getGasLimit() : BigInteger.ZERO),
                this.getToAddress() != null ? this.getToAddress() : "0x",
                Numeric.toHexStringWithPrefix(this.getValue() != null ? this.getValue() : BigInteger.ZERO),
                this.getData() != null ? Numeric.toHexString(this.getData()) : "",
                Numeric.toHexStringWithPrefix(this.getMaxFeePerGas() != null ? this.getMaxFeePerGas() : BigInteger.ZERO),
                Numeric.toHexStringWithPrefix(this.getMaxPriorityFeePerGas() != null ? this.getMaxPriorityFeePerGas() : BigInteger.ZERO),
                (isSigned() && checkSignatureData(getSignatureData())) ? new SignatureSecp256k1(getSignatureData()).toString() : ""
            );
        else
            return String.format(
                "EthereumTransaction{id=%s, from=%s, nonce=%s, gasPrice=%s, gasLimit=%s, to=%s, value=%s, data=%s, " +
                        "Signature=%s}",
                id(),
                getFromAddress(),
                Numeric.toHexStringWithPrefix(this.getNonce() != null ? this.getNonce() : BigInteger.ZERO),
                Numeric.toHexStringWithPrefix(this.getGasPrice() != null ? this.getGasPrice() : BigInteger.ZERO),
                Numeric.toHexStringWithPrefix(this.getGasLimit() != null ? this.getGasLimit() : BigInteger.ZERO),
                this.getToAddress() != null ? this.getToAddress() : "0x",
                Numeric.toHexStringWithPrefix(this.getValue() != null ? this.getValue() : BigInteger.ZERO),
                this.getData() != null ? Numeric.toHexString(this.getData()) : "",
                (isSigned() && checkSignatureData(getSignatureData())) ? new SignatureSecp256k1(getSignatureData()).toString() : ""
        );
    }

    @Override
    public byte[] messageToSign() {
        if (this.transaction.getType().isLegacy() && this.isSigned()) {
            // the chainid might be set also in legacy case due to EIP155
            return ((SignedRawTransaction) this.transaction).getEncodedTransaction(this.getChainId());
        }
        return TransactionEncoder.encode(this.transaction);
    }

    public Message asMessage(BigInteger baseFee) {
        // both methods defaults to gasPrice if not EIP1559
        var gasFeeCap = getMaxFeePerGas();
        var gasTipCap = getMaxPriorityFeePerGas();
        // calculate effective gas price as baseFee + tip capped at the fee cap
        // this will default to gasPrice if the transaction is not EIP-1559
        var effectiveGasPrice = baseFee.add(gasTipCap).min(gasFeeCap);
        return new Message(
                getFrom(),
                getTo(),
                effectiveGasPrice,
                gasFeeCap,
                gasTipCap,
                getGasLimit(),
                getValue(),
                getNonce(),
                getData(),
                false
        );
    }
}
