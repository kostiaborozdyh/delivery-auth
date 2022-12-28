package com.delivery.auth.server.controllers;

import com.delivery.auth.config.service.TokenProvider;
import com.delivery.auth.config.dto.TokenDTO;
import com.delivery.auth.server.service.UserJwtService;
import io.jsonwebtoken.JwtException;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthenticateController {

    private final TokenProvider tokenProvider;
    private final UserJwtService userJwtService;

    @PostMapping("/refreshToken")
    public ResponseEntity<TokenDTO> refreshToken(HttpServletRequest request) {
        String refreshToken = tokenProvider.getJwtFromRequest(request);

        if(!tokenProvider.validateJwtRefreshToken(refreshToken)){
            throw new JwtException("Not valid JWT Refresh Token");
        }

        try {
            String username = tokenProvider.getUsernameFromToken(refreshToken);
            String token = tokenProvider.generateToken(username, userJwtService.getUserAuthorities(username));

            return new ResponseEntity<>(new TokenDTO(token), HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Unable to get JWT Refresh Token");
        }
    }
}
