package com.horizen.validation;

/*
 * Exception could be thrown by any CustomBlockValidator during applying to the Node
 * if the verified block has data inconsistent to the main/header part.
 * In case of InconsistentDataCustomValidatorException only the sender will be banned.
 */
public class InconsistentDataCustomValidatorException extends InconsistentDataException {
    public InconsistentDataCustomValidatorException() {
        super("", scala.Option.empty());
    }

    public InconsistentDataCustomValidatorException(String message) {
        super(message, scala.Option.empty());
    }

    public InconsistentDataCustomValidatorException(String message, Throwable cause) {
        super(message, scala.Option.apply(cause));
    }

    public InconsistentDataCustomValidatorException(Throwable cause) {
        super("", scala.Option.apply(cause));
    }
}
