package com.horizen.validation;

/*
 * Exception could be thrown by any CustomBlockValidator during applying to the Node
 * if the verified block has data which can't be checked at the moment or block/data was received too early.
 * In case of BlockInFutureCustomValidatorException block and sender will not be banned.
 */
public class BlockInFutureCustomValidatorException extends BlockInFutureException {
    public BlockInFutureCustomValidatorException() {
        super("", scala.Option.empty());
    }

    public BlockInFutureCustomValidatorException(String message) {
        super(message, scala.Option.empty());
    }

    public BlockInFutureCustomValidatorException(String message, Throwable cause) {
        super(message, scala.Option.apply(cause));
    }

    public BlockInFutureCustomValidatorException(Throwable cause) {
        super("", scala.Option.apply(cause));
    }
}
