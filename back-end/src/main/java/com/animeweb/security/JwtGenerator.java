package com.animeweb.security;

import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.repository.ExpiredTokenRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;

@Component
public class JwtGenerator {

    @Autowired
    ExpiredTokenRepository expiredTokenRepository;
    public String generateToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime()+SecurityConstants.JWT_EXPIRATION);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUserName())
                .issuer("animeweb.site")
                .issueTime(currentDate)
                .expirationTime(expireDate)
                .claim("idUser",user.getId())
                .claim("fullName",user.getFullName())
                .jwtID(UUID.randomUUID().toString())
                .claim("avt",user.getAvatarPicture())
                .claim("scope",(buildScopeUser(user.getRoles()))).build();
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header,payload);
        try{
            jwsObject.sign(new MACSigner(SecurityConstants.JWT_SECRET.getBytes()));
            return jwsObject.serialize();
        }catch (JOSEException e){
            throw new RuntimeException(e);
        }
    }


    private String buildScopeUser(List<Role> roles){
        StringJoiner stringJoiner = new StringJoiner(" ");
        if (!CollectionUtils.isEmpty(roles)){
            roles.forEach(role -> {
                stringJoiner.add("ROLE_"+role.getName());
                if(!CollectionUtils.isEmpty(role.getPermissions())){
                    role.getPermissions().forEach(permission -> {
                        stringJoiner.add(permission.getName());
                    });
                }
            });
        }
        return stringJoiner.toString();
    }
    public SignedJWT verifyToken(String token,boolean isRefresh){
        try{
        JWSVerifier verifier = new MACVerifier(SecurityConstants.JWT_SECRET.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date expiryTime = isRefresh ? new Date(signedJWT.getJWTClaimsSet().getIssueTime().getTime()+SecurityConstants.JWT_REFRESH):signedJWT.getJWTClaimsSet().getExpirationTime();
        boolean verified = signedJWT.verify(verifier);
        if (!(verified && expiryTime.after(new Date())))  throw new AuthenticationCredentialsNotFoundException("Invalid JWT token");
        if(expiredTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))  throw new AuthenticationCredentialsNotFoundException("JWT expired");
        return signedJWT;
        } catch (ParseException | JOSEException e) {
            throw new AuthenticationCredentialsNotFoundException("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            throw new AuthenticationCredentialsNotFoundException("JWT expired", e);
        }
    }

}
