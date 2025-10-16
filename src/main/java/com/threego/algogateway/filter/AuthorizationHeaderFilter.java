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
            String path = request.getURI().getPath();

            // Authorization 헤더 없으면 에러 반환
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            // JWT 추출
            String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization header format", HttpStatus.UNAUTHORIZED);
            }
            String jwt = bearerToken.substring(7);

            // 유효성 검사
            // JWT 유효성 검증
            Claims claims;
            try {
                claims = Jwts.parser()
                        .setSigningKey(env.getProperty("token.secret"))
                        .parseClaimsJws(jwt)
                        .getBody();
            } catch (Exception e) {
                log.error("JWT 검증 실패: {}", e.getMessage());
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            // Claim 추출 (타입 안정적으로 변환)
            String memberId = String.valueOf(claims.get("memberId"));
            String role = String.valueOf(claims.get("role"));
            String email = claims.getSubject();
            String nickname = String.valueOf(claims.get("nickname"));

            log.info(">>> 인증된 사용자: memberId={}, role={}, email={}", memberId, role, email);

            // 관리자 경로 접근 제한 (/admin/**)
            if (path.startsWith("/admin")) {
                boolean isAdmin = "ROLE_ADMIN".equals(role) || "ADMIN".equals(role);
                if (!isAdmin) {
                    return onError(exchange, "Access denied: ADMIN role required", HttpStatus.FORBIDDEN);
                }
            }

            // 사용자 정보를 헤더에 추가하여 다음 서비스로 전달
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-Member-Id", memberId)
                    .header("X-Role", role)
                    .header("X-Email", email)
                    .header("X-Nickname", nickname)
                    .build();

            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(modifiedRequest)
                    .build();

            return chain.filter(modifiedExchange);
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
        log.warn("요청 차단됨: {} (httpStatus={})", errorMessage, httpStatus);
        return response.setComplete();
    }
}
