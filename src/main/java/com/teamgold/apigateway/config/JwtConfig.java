package com.teamgold.apigateway.config;

import com.teamgold.apigateway.security.JwtVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Bean
    public JwtVerifier jwtVerifier(@Value("${jwt.secret-key}") String secret) {
        return new JwtVerifier(secret);
    }
}
