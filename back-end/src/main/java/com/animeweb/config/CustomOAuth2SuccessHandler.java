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
        Cookie[] cookies = request.getCookies();

        String sessionId = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    sessionId = cookie.getValue();
                    System.out.println("JSESSIONID = " + sessionId);
                    break;
                }
            }
        } else {
            System.out.println("No cookies found in the request");
        }
        String redirectUrl = determineRedirectUrl(authentication,sessionId);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    protected String determineRedirectUrl(Authentication authentication, String sessionId) {
        String provider = authentication.getPrincipal().toString();
        String redirectUrl;

        if (provider.contains("google")) {
            redirectUrl = "https://animewebnew.netlify.app/login-google";
        } else {
            redirectUrl = "https://animewebnew.netlify.app/login-facebook";
        }
        if (sessionId != null) {
            redirectUrl = redirectUrl + "?sessionId=" + sessionId;
        }

        return redirectUrl;
    }

}

