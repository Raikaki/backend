package com.animeweb.dto.oauth;

import lombok.Data;
import lombok.NonNull;

@Data
public class VerifyUser {
    @NonNull
    private String userName;
    @NonNull
    private String email;
    @NonNull
    private Integer verifyCode;
}
