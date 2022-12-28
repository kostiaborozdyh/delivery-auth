package com.delivery.auth.server.controllers;

import com.delivery.auth.config.dto.ErrorMessageDTO;
import javax.servlet.http.HttpServletRequest;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ControllerAdvice {

    @ExceptionHandler(value = JwtException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorMessageDTO handleAuthenticateException(JwtException ex, HttpServletRequest request) {
        return new ErrorMessageDTO(
                HttpStatus.FORBIDDEN.value(),
                ex.getMessage(),
                request.getServletPath());
    }
}
