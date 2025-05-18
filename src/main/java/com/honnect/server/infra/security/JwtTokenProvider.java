package com.honnect.server.infra.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Component;



@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final Long expirationTime;



    public JwtTokenProvider(JwtTokenProperties properties) {
        this.key = Keys.hmacShaKeyFor(properties.secretKey().getBytes(StandardCharsets.UTF_8));
        this.expirationTime = properties.expirationTime();
    }

    public String generateToken(UserPrincipal userPrincipal) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationTime);

        return Jwts.builder()
                .subject(userPrincipal.getId().toString())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(key)
                .compact();
    }
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            // 예외 처리 (로그 기록 또는 사용자 알림용)
            // SignatureException, MalformedJwtException, ExpiredJwtException 등은 JwtException을 상속
        }
        return false;
    }

    public String getUserIdFromJWT(String jwt) {
        Claims claims = (Claims) Jwts.parser() // parser() 대신 parserBuilder() 사용
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getBody();

        return claims.getSubject();
    }
}
