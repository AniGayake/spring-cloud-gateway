package com.banking.spring.cloud.gateway.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path =exchange.getRequest().getURI().getPath();

        List<String> openEndpoints = List.of("/api/customer/registration","/api/auth/login");

        if(openEndpoints.stream().anyMatch(path::startsWith)){
            return chain.filter(exchange);
        }
        String token = extractToken(exchange);
        if(null==token){
            LOGGER.error("Missing Authorization Error");
            return jsonErrorResponse(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);

        }

        try {
            Claims claims= Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            exchange.getRequest().mutate()
                    .header("x-user-id", claims.getSubject())
                    .build();

        }catch (ExpiredJwtException e) {
            return jsonErrorResponse(exchange, "Token expired", HttpStatus.UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            return jsonErrorResponse(exchange, "Malformed token", HttpStatus.UNAUTHORIZED);
        } catch (SignatureException e) {
            return jsonErrorResponse(exchange, "Invalid token signature", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return jsonErrorResponse(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        }
        return chain.filter(exchange);

    }
    private String extractToken(ServerWebExchange exchange){
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if(authHeader!=null && authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;
    }


    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }
    private Mono<Void> jsonErrorResponse(ServerWebExchange exchange, String message, HttpStatus status) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String path = exchange.getRequest().getPath().value();
        String body = String.format("""
            {
              "timestamp": "%s",
              "status": %d,
              "error": "%s",
              "message": "%s",
              "path": "%s"
            }
            """,
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                status.value(),
                status.getReasonPhrase(),
                message,
                path
        );

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        var buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
