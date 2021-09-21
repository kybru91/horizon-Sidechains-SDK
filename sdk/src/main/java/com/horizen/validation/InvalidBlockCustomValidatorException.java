package com.horizen.validation;

/*
 * Exception could be thrown by any CustomBlockValidator during applying to the Node
 * if the verified block is invalid.
 * In case of InvalidBlockCustomValidatorException both the sender and the block will be banned.
 */
public class InvalidBlockCustomValidatorException extends InvalidBlockException{
    public InvalidBlockCustomValidatorException() {
        super("", scala.Option.empty());
    }

    public InvalidBlockCustomValidatorException(String message) {
        super(message, scala.Option.empty());
    }

    public InvalidBlockCustomValidatorException(String message, Throwable cause) {
        super(message, scala.Option.apply(cause));
    }

    public InvalidBlockCustomValidatorException(Throwable cause) {
        super("", scala.Option.apply(cause));
    }
}
