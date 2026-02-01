package com.teamgold.apigateway.filter;

import com.teamgold.apigateway.security.JwtVerifier;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    private final JwtVerifier jwtTokenVerifier;

    private static final List<String> PERMIT_PREFIX = List.of(
            "/api/auth/",
            "/actuator",
            "/swagger-ui",
            "/v3/api-docs",
            "/api/chat",
            "/api/documents"
    );

    public JwtAuthGlobalFilter(JwtVerifier jwtTokenVerifier) {
        this.jwtTokenVerifier = jwtTokenVerifier;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        String method = String.valueOf(exchange.getRequest().getMethod());
        log.debug("[GW] incoming {} {}", method, path);

        if (HttpMethod.OPTIONS.matches(method)) {
            log.debug("[GW] OPTIONS preflight -> pass");
            return chain.filter(exchange);
        }

        if (isPermit(path)) {
            log.debug("[GW] permit path -> pass");
            return chain.filter(exchange);
        }

        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.startsWith("Bearer ")) {
            exchange.getResponse().getHeaders().add("X-GW-REJECT", "no-bearer");

            log.warn("[GW] reject: no bearer token. path={}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = auth.substring(7);

        if (!jwtTokenVerifier.validateToken(token)) {
            exchange.getResponse().getHeaders().add("X-GW-REJECT", "bad-jwt");

            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims = jwtTokenVerifier.getClaimsAllowExpired(token);

        String email = claims.getSubject();
        Object role = claims.get("role");


        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .header("X-User-Email", email == null ? "" : email)
                .header("X-User-Role", role == null ? "" : String.valueOf(role))
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private boolean isPermit(String path) {
        return PERMIT_PREFIX.stream().anyMatch(path::startsWith);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
