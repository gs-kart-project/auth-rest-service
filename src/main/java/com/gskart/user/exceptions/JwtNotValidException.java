package com.gskart.user.exceptions;

public class JwtNotValidException extends Exception {
    public JwtNotValidException(String message, Throwable cause) {
        super(message, cause);
    }
}
