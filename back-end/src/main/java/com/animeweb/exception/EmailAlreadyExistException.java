package com.animeweb.exception;

public class EmailAlreadyExistException extends RuntimeException {

    public EmailAlreadyExistException() {
    }

    public EmailAlreadyExistException(String message) {
        super(message);
    }
}
