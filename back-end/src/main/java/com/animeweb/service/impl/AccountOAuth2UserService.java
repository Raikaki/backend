package com.animeweb.service.impl;

import com.animeweb.entities.User;
import com.animeweb.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AccountOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

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
