package com.animeweb.config;

import com.animeweb.dto.oauth.AuthResponseDTO;
import com.animeweb.dto.user.SocialUser;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.mapper.SocialUserMapper;
import com.animeweb.repository.RoleRepository;
import com.animeweb.security.JwtGenerator;
import com.animeweb.service.impl.AccountOAuth2UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    AccountOAuth2UserService accountOAuth2UserService;
    @Autowired
    JwtGenerator jwtGenerator;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String redirectUrl = determineRedirectUrl(authentication);
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttribute("email");
        String name = (String) oAuth2User.getAttribute("name");
        String givenName = (String) oAuth2User.getAttribute("given_name");
        String id = (String) oAuth2User.getAttribute("sub");
        String pictureUrl = (String) oAuth2User.getAttribute("picture");
        System.out.println("email: "+email);
        User socialUser = accountOAuth2UserService.findByEmailGoogle(email);
        SocialUser socialUser1;
        String token = "";
        Date now = java.sql.Date.valueOf(LocalDate.now());
    if (socialUser == null) {
        String pass = null;
        try {
            pass = com.animeweb.config.HashAlgorithm.hashText(id, com.animeweb.config.HashAlgorithm.SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Role roles = roleRepository.findByNameAndStatusTrue("USER");

        socialUser1 = new SocialUser(null, name, pictureUrl, pass, email, name, null, 2, now, null, null, true, id, null, null, null);
        socialUser1.setRole(roles);

        User socialUser2 = SocialUserMapper.mapToEntity(socialUser1);
        socialUser2.setIsActive(true);
        socialUser2.setRoles(Collections.singletonList(roles));

        accountOAuth2UserService.createAccount(socialUser2);
        token = jwtGenerator.generateToken(socialUser2);
    } else {
        token = jwtGenerator.generateToken(socialUser);

    }
    getRedirectStrategy().sendRedirect(request, response, redirectUrl + "?token="+token);

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
