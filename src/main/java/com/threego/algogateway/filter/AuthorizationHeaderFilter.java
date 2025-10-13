package com.threego.algogateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

/* 설명. 게이트웨이에서 토큰 유효성 검사를 위한 필터 */
@Component
@Slf4j
public class AuthorizationHeaderFilter
        extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final Environment env;

    @Autowired
    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // Authorization 헤더 없으면 에러 반환
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            // JWT Token 추출
            String bearerToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = bearerToken.substring(7);

            // 유효성 검사
            String subject = getSubject(jwt);
            if (subject == null) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            Claims claims = Jwts.parser()
                    .setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt)
                    .getBody();

            String memberId = claims.get("memberId", String.class);
            String role = claims.get("role", String.class);
            String email = claims.getSubject();
            String nickname = claims.get("nickname", String.class);

            // 요청 헤더에 사용자 정보 추가
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-Member-Id", memberId)
                    .header("X-Role", role)
                    .header("X-Email", email)
                    .header("X-Nickname", nickname)
                    .build();

            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(modifiedRequest)
                    .build();

            return chain.filter(exchange);
        };
    }

    private String getSubject(String jwt) {
        try {
            return Jwts.parser()
                    .setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.info("에러 메시지: {}", errorMessage);

        return response.setComplete();
    }
}
