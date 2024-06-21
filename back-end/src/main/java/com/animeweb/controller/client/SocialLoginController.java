package com.animeweb.controller.client;

import com.animeweb.config.HashAlgorithm;
import com.animeweb.dto.oauth.AuthResponseDTO;
import com.animeweb.dto.user.SocialUser;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.mapper.SocialUserMapper;
import com.animeweb.repository.RoleRepository;
import com.animeweb.security.JwtGenerator;
import com.animeweb.service.impl.AccountOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

@RestController
public class SocialLoginController {
    @Autowired
    AccountOAuth2UserService accountOAuth2UserService;
    @Autowired
    private JwtGenerator jwtGenerator;
    @Autowired
    RoleRepository roleRepository;
    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping("/login/google")
    public ResponseEntity<AuthResponseDTO> getUser(@AuthenticationPrincipal OAuth2User oAuth2User) throws NoSuchAlgorithmException {
        String email = (String) oAuth2User.getAttribute("email");
        String name = (String) oAuth2User.getAttribute("name");
        String givenName = (String) oAuth2User.getAttribute("given_name");
        String id = (String) oAuth2User.getAttribute("sub");
        String pictureUrl = (String) oAuth2User.getAttribute("picture");
        User socialUser = accountOAuth2UserService.findByEmailGoogle(email);
        SocialUser socialUser1 =null;
        String token = "";
        Date now = java.sql.Date.valueOf(LocalDate.now());
        if (socialUser == null) {
            String pass= HashAlgorithm.hashText(id,HashAlgorithm.SHA256);
            Role roles = roleRepository.findByNameAndStatusTrue("USER");
            socialUser1 = new SocialUser(null, name, pictureUrl, pass, email, name, null, 2, now, null, null, true, id, null, null, null);
            socialUser1.setRole(roles);
            User  socialUser2 = SocialUserMapper.mapToEntity(socialUser1);
            socialUser2.setRoles(Collections.singletonList(roles));
            accountOAuth2UserService.createAccount(socialUser2);
           token = jwtGenerator.generateToken(socialUser2);
            return new ResponseEntity<>(new AuthResponseDTO(token,true),HttpStatus.OK);
        }else{
            token =  jwtGenerator.generateToken(socialUser);
            return new ResponseEntity<>(new AuthResponseDTO(token,true), HttpStatus.OK);

        }

    }
    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping("/login/facebook")
    public ResponseEntity<AuthResponseDTO> getUserFacebook(@AuthenticationPrincipal OAuth2User oAuth2User) throws NoSuchAlgorithmException {
        String email = (String) oAuth2User.getAttribute("email");
        String name = (String) oAuth2User.getAttribute("name");
        String id = (String) oAuth2User.getAttribute("id");
        String pictureUrl = null;
        System.out.println("ACCOUNT FB"+oAuth2User.getAttributes());
        Map<String, Map<String, Object>> pictureData = oAuth2User.getAttribute("picture");
        if (pictureData != null) {
            Map<String, Object> data = pictureData.get("data");
            if (data != null) {
                pictureUrl = (String) data.get("url");
            }
        }

        // Retrieve roles safely
        Role roles = roleRepository.findByNameAndStatusTrue("USER");
        User socialUser = accountOAuth2UserService.findByEmailFacebook(email);
        Date now = java.sql.Date.valueOf(LocalDate.now());
        String token;
        SocialUser socialUser1 ;

        if (socialUser == null) {
            String pass= HashAlgorithm.hashText(id,HashAlgorithm.SHA256);
           socialUser1 = new SocialUser(roles, name, pictureUrl, pass, email, name, null, 3, now, null, null, true, id, null, null, null);
            socialUser1.setRole(roles);
            User socialUser2 = SocialUserMapper.mapToEntity(socialUser1);
            System.out.println(socialUser1);
            System.out.println(socialUser2);
            socialUser2.setRoles(Collections.singletonList(roles));
            accountOAuth2UserService.createAccount(socialUser2);

             token = jwtGenerator.generateToken(socialUser2);
            return new ResponseEntity<>(new AuthResponseDTO(token, true), HttpStatus.OK);
        } else {
            token = jwtGenerator.generateToken(socialUser);
            return new ResponseEntity<>(new AuthResponseDTO(token, true), HttpStatus.OK);
        }
    }



}