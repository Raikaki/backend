package com.animeweb.dto.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateUser {
    private Long id;
    private String userName;
    private MultipartFile avatarPicture;
    private String email;
    private String fullName;
    private String phone;
}
