package io.horizen.account.api.rpc.types;

import io.horizen.account.chain.AccountFeePaymentsInfo;
import io.horizen.account.utils.AccountPayment;
import io.horizen.evm.Address;
import scala.collection.JavaConverters;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;

public class FeePaymentsView {
    public final List<FeePaymentData> payments;

    public FeePaymentsView(AccountFeePaymentsInfo info) {
        payments = JavaConverters
            .seqAsJavaList(info.payments())
            .stream()
            .map(payment -> FeePaymentData.fromAccountFeePayment(payment))
            .collect(Collectors.toList());
    }

    private static class FeePaymentData {
        public final Address address;
        public final BigInteger value;
        public final BigInteger valueFromMainchain;
        public final BigInteger valueFromFees;

        public FeePaymentData(Address address, BigInteger value, BigInteger valueFromMainchain, BigInteger valueFromFees) {
            this.address = address;
            this.value = value;
            this.valueFromMainchain = valueFromMainchain;
            this.valueFromFees = valueFromFees;
        }

        public static FeePaymentData fromAccountFeePayment(AccountPayment payment) {
            return new FeePaymentData(
                payment.address().address(),
                payment.value(),
                payment.valueFromMainchain().getOrElse(() -> BigInteger.ZERO),
                payment.valueFromFees().getOrElse(() -> BigInteger.ZERO)
            );
        }
    }
}
