package com.animeweb.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String sessionId = getSessionIdFromCookie(request);
        if (sessionId != null) {
            response.setHeader("JSESSIONID", sessionId);
        }
        String encodedUser = Base64.getEncoder().encodeToString(authentication.getPrincipal().toString().getBytes(StandardCharsets.UTF_8));
        Cookie userCookie = new Cookie("oAuth2User", encodedUser);
        userCookie.setPath("/");
        userCookie.setHttpOnly(true);
        userCookie.setMaxAge(60 * 60);
        response.addCookie(userCookie);
        String redirectUrl = determineRedirectUrl(authentication);
        try{
            getRedirectStrategy().sendRedirect(request, response, redirectUrl + "?jsessionid="+sessionId);

        }catch (Exception e){
            System.out.println("loi ne: " +e.getMessage());
        }
    }

    protected String determineRedirectUrl(Authentication authentication) {
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
