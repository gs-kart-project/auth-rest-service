package com.gskart.user.exceptions;

public class UserNotExistsException extends Exception {
    public UserNotExistsException(String message) {
        super(message);
    }
}
