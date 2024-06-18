package com.animeweb.dto.user;

import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Data
public class RegisterDTO {
    private String userName;
    private String password;
    private String email;
    private String fullName;
    private String phone;

}
