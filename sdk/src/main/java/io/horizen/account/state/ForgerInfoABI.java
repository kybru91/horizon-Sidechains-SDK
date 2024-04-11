package io.horizen.account.state;

import org.web3j.abi.datatypes.StaticStruct;
import org.web3j.abi.datatypes.generated.Bytes1;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint32;

import java.math.BigInteger;

public class ForgerInfoABI extends StaticStruct {
    public byte[] pubKey;
    public byte[] vrf1;
    public byte[] vrf2;
    public int rewardShare;
    public String rewardAddress;

    public ForgerInfoABI(byte[] pubKey, byte[] vrf1, byte[] vrf2, int rewardShare, String rewardAddress) {
        super(
                new Bytes32(pubKey),
                new Bytes32(vrf1),
                new Bytes1(vrf2),
                new Uint32(rewardShare),
                new org.web3j.abi.datatypes.Address(rewardAddress)
                );
        this.pubKey = pubKey;
        this.vrf1 = vrf1;
        this.vrf2 = vrf2;
        this.rewardShare = rewardShare;
        this.rewardAddress = rewardAddress;
    }

    public ForgerInfoABI(Bytes32 pubKey, Bytes32 vrf1, Bytes1 vrf2, Uint32 rewardShare, org.web3j.abi.datatypes.Address rewardAddress) {
        super(pubKey, vrf1, vrf2, rewardShare, rewardAddress);
        this.pubKey = pubKey.getValue();
        this.vrf1 = vrf1.getValue();
        this.vrf2 = vrf2.getValue();
        this.rewardShare = rewardShare.getValue().intValueExact();
        this.rewardAddress = rewardAddress.getValue();
    }

}
