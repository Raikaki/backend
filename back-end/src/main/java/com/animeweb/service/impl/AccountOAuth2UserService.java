package com.animeweb.service.impl;

import com.animeweb.entities.User;
import com.animeweb.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AccountOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        return super.loadUser(userRequest);
    }

    public User findByEmailGoogle(String email) {
        return userRepository.findByEmailGoogle(email);
    }

    public User findByEmailFacebook(String email) {
        return userRepository.findByEmailFacebook(email);
    }

    public void createAccount(User socialUser) {
        userRepository.save(socialUser);
    }
}
