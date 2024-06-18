package com.animeweb.security;

import com.animeweb.service.impl.UserServiceImpl;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Objects;

@Component
public class CustomJwtDecoder implements JwtDecoder {

    @Autowired
    UserServiceImpl userService;
    private NimbusJwtDecoder nimbusJwtDecoder = null;
    @Override
    public Jwt decode(String token) throws JwtException {
       IntrospectRequest introspectRequest = new IntrospectRequest();
       introspectRequest.setToken(token);
        try {
            IntrospectResponse introspectResponse = userService.introspect(introspectRequest);
            if(!introspectResponse.isValid()) throw new JwtException("Token invalid");
        } catch (ParseException|JOSEException e) {
            throw new RuntimeException(e);
        }
        if (Objects.isNull(nimbusJwtDecoder)){
            SecretKeySpec secretKeySpec = new SecretKeySpec(SecurityConstants.JWT_SECRET.getBytes(), JWSAlgorithm.HS256.getName());
            nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm(MacAlgorithm.HS256).build();
        }
        return nimbusJwtDecoder.decode(token);
    }
}
