package com.horizen.account.api.rpc.handler;

import com.horizen.account.api.rpc.utils.RpcError;

public class RpcException extends Exception {
    public RpcError error;

    public RpcException(RpcError error) {
        super(error.toString());
        this.error = error;
    }
}
