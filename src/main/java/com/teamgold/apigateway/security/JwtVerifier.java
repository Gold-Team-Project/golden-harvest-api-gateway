package com.teamgold.apigateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Slf4j
@Component
public class JwtVerifier {

    private final SecretKey secretKey;

    public JwtVerifier(@Value("${jwt.secret-key}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;

        } catch (ExpiredJwtException e) {
            String sub = (e.getClaims() != null) ? e.getClaims().getSubject() : "null";
            log.warn("[GW][JWT] expired token. sub={}", sub);

        } catch (SecurityException e) {
            log.warn("[GW][JWT] signature invalid.");

        } catch (MalformedJwtException e) {
            log.warn("[GW][JWT] malformed token.");

        } catch (IllegalArgumentException e) {
            log.warn("[GW][JWT] illegal/empty token.");

        } catch (Exception e) {
            log.warn("[GW][JWT] unknown error: {}", e.toString());
        }
        return false;
    }

    public Claims getClaimsAllowExpired(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("[GW][JWT] claims read from expired token.");
            return e.getClaims();
        }
    }

    private static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "ERR";
        }
    }
}
