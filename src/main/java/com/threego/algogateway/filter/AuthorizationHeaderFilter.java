package com.threego.algogateway.filter;

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

    /* 설명. Application.yml에서부터 토큰관련 설정값을 불러오기 위해서 */
    Environment env;

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

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            /* 설명. 토큰을 들고 왔다면 추가 검증 */
            HttpHeaders headers = request.getHeaders();  // springframework 패키지로 import할 것!

            /* 설명. request header에 담긴 값들을 로그로 확인 */
            Set<String> keys = headers.keySet();
            log.info(">>>");
            keys.stream().forEach(v -> {
                log.info(v + "=" + request.getHeaders().get(v));
            });
            log.info("<<<");

            /* 설명. "Authorization"이라는 키 값으로 넘어온 request header에 담긴 토큰 추출(JWT Token) */
            String bearerToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = bearerToken.substring(7);

            if(!isJwtValid(jwt)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    /* 설명. 토큰 유효성 검사용 메소드 */
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;

        /* 설명. 기본적으로 우리 서버에서 만들었고, 만료기간이 지나지 않았으며, 토큰 안에 'sub'라는 등록된
         *      클레임이 있는지 확인
         * */
        try {
            subject = Jwts.parser()
                    .setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            returnValue = false;
        }

        /* 설명. 토큰의 payload에 subject 클레임 자체가 없거나 내용물이 없거나 */
        if(subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }

    /* 설명. Mono는 아무 데이터도 반환하지 않고, 비동기적으로 완료됨을 나타내는 반환타입 */
    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.info("에러 메시지: {}", errorMessage);

        return response.setComplete();
    }
}
