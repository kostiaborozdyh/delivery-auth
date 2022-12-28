package com.delivery.auth.config.filter;

import com.delivery.auth.config.service.TokenProvider;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@AllArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final List<String> IGNORE_FILTER_PATHS = Arrays.asList("/refreshToken", "/login");

    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String jwtToken = tokenProvider.getJwtFromRequest(request);

        if (Objects.nonNull(jwtToken) && tokenProvider.validateJwtToken(jwtToken)) {
            String username = tokenProvider.getUsernameFromToken(jwtToken);
            Set<GrantedAuthority> authorities = tokenProvider.getAuthorities(jwtToken);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            log.warn("Clearing security context since auth token is not present/valid!");
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return IGNORE_FILTER_PATHS.contains(request.getServletPath());
    }
}
