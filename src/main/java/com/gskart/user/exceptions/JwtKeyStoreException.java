package com.gskart.user.exceptions;

public class JwtKeyStoreException extends Exception {
    public JwtKeyStoreException(String message) {
        super(message);
    }

    public JwtKeyStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
