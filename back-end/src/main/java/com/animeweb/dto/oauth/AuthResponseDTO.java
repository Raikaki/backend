package com.animeweb.dto.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.Data;

@Data
public class AuthResponseDTO {
    private String accessToken;
    private String tokenType ="Bearer ";
    private boolean authenticated = false;
    private String message;

    public AuthResponseDTO(String accessToken,boolean authenticated) {
        this.accessToken = accessToken;
        this.authenticated = authenticated;
    }
    public AuthResponseDTO(String message) {
        this.message = message;
    }
}
