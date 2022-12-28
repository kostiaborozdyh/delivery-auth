package com.delivery.auth.config.service;

import com.delivery.auth.config.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenProvider {

    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String AUTHORITIES = "authorities";
    private static final String AUTHORITY = "authority";

    private final AppProperties appProperties;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Set<GrantedAuthority> getAuthorities(String token) {
        List<Map<String, String>> authorities =
                (List<Map<String, String>>) getAllClaimsFromToken(token).get(AUTHORITIES);

        if (authorities == null) {
            return Collections.emptySet();
        }
        return authorities.stream()
                .map(authority -> new SimpleGrantedAuthority(authority.get(AUTHORITY)))
                .collect(Collectors.toSet());
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);

        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(appProperties.getTokenSecret())
                .parseClaimsJws(token)
                .getBody();
    }

    public String getJwtFromRequest(HttpServletRequest request) {
        String authHeaderFromHeader = getAuthHeaderFromHeader(request);

        if (Objects.nonNull(authHeaderFromHeader) && authHeaderFromHeader.startsWith(TOKEN_PREFIX)) {
            return authHeaderFromHeader.substring(TOKEN_PREFIX.length());
        }

        return null;
    }

    private String getAuthHeaderFromHeader(HttpServletRequest request) {
        return request.getHeader(HttpHeaders.AUTHORIZATION);
    }

    public boolean validateJwtToken(String jwtToken) {
        try {
            Jwts.parser().setSigningKey(appProperties.getTokenSecret()).parseClaimsJws(jwtToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature", e);
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token", e);
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.", e);
        } catch (JwtException e) {
            log.error("JWT is not walid.", e);
        }

        return false;
    }

    public boolean validateJwtRefreshToken(String jwtToken) {

        return getAllClaimsFromToken(jwtToken).get(AUTHORITIES) == null;
    }

    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(AUTHORITIES, authorities);

        return generateToken(claims, username, appProperties.getTokenExpirationMsec());
    }

    private String generateToken(Map<String, Object> claims, String subject, long timeExpirationMSec) {
        return TOKEN_PREFIX + Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(getExpirationDate(timeExpirationMSec))
                .signWith(SignatureAlgorithm.HS512, appProperties.getTokenSecret())
                .compact();
    }

    private Date getExpirationDate(long timeExpirationMSec) {
        return new Date(System.currentTimeMillis() + timeExpirationMSec);
    }

    public String generateRefreshToken(String username) {
        return generateToken(new HashMap<>(), username, appProperties.getTokenRefreshExpirationMsec());
    }
}
