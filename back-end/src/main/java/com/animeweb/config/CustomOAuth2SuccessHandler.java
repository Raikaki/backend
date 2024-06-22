package com.animeweb.config;

import jakarta.servlet.http.Cookie;
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
        String sessionId = getSessionIdFromCookie(request);
        if (sessionId != null) {
            response.setHeader("JSESSIONID", sessionId);
        }
        System.out.println(sessionId);
        System.out.println(authentication.getPrincipal().toString());
        String redirectUrl = determineRedirectUrl(authentication, sessionId);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    protected String determineRedirectUrl(Authentication authentication, String sessionId) {
        String provider = authentication.getPrincipal().toString();
        String baseUrl = "https://animewebnew.netlify.app";

        if (provider.contains("google")) {
            return baseUrl + "/login-google";
        } else {
            return baseUrl + "/login-facebook";
        }
    }

    protected String getSessionIdFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
