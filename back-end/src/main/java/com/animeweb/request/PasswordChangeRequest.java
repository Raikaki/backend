package com.animeweb.request;

public record PasswordChangeRequest(
        String oldPassword,
        String newPassword,
        String confirmPassword
) {
}
