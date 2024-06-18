package com.animeweb.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String redirectUrl = determineRedirectUrl(authentication);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    protected String determineRedirectUrl(Authentication authentication) {
        String provider = authentication.getPrincipal().toString();
        if (provider.contains("google")) {
            return "http://localhost:3000/login-google";
        } else
            return "http://localhost:3000/login-facebook";
    }

}

