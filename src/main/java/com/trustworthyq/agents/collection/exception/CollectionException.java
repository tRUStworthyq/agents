package com.trustworthyq.agents.collection.exception;

public class CollectionException extends RuntimeException {
    private final String code;

    public CollectionException(String code, Throwable cause) {
        super(code, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
