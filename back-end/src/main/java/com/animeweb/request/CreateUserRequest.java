package com.animeweb.request;

import org.springframework.web.multipart.MultipartFile;

public record CreateUserRequest(
        String name,
        String phone,
        String email,
        String username,
        String password,
        MultipartFile avatarPicture
) {
}
