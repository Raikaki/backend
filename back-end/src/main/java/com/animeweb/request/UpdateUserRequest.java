package com.animeweb.request;

import org.springframework.web.multipart.MultipartFile;

public record UpdateUserRequest(
        String name,
        String phone,
        String email,
        MultipartFile avatarPicture,
        String username,
        String password
        ) {
    public UpdateUserRequest {

    }
}
