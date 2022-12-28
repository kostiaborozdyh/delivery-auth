package com.delivery.auth.config.filter;

import com.delivery.auth.config.exception.FailedAuthenticationException;
import com.delivery.auth.config.dto.JwtResponseDTO;
import com.delivery.auth.config.dto.UserAuthenticationRequestDTO;
import com.delivery.auth.config.service.TokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final String FAILED_TO_AUTHENTICATE_USER_ERROR_MESSAGE = "Failed to authenticate user";

    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        try {
            UserAuthenticationRequestDTO authenticationRequest = objectMapper
                    .readValue(request.getInputStream(), UserAuthenticationRequestDTO.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            return authenticationManager.authenticate(authentication);
        } catch (IOException e) {
            log.error(FAILED_TO_AUTHENTICATE_USER_ERROR_MESSAGE, e);
            throw new FailedAuthenticationException(FAILED_TO_AUTHENTICATE_USER_ERROR_MESSAGE);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException {

        final String token = tokenProvider.generateToken(authResult.getName(), authResult.getAuthorities());
        final String refreshToken = tokenProvider.generateRefreshToken(authResult.getName());

        JwtResponseDTO jwtResponseDTO = new JwtResponseDTO(token, refreshToken, authResult.getName());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(objectMapper.writeValueAsString(jwtResponseDTO));
    }
}
