package com.delivery.auth.config.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
public class ErrorMessageDTO {
    private final Integer status;
    private final LocalDateTime time = LocalDateTime.now();
    private String message;
    private String uri;
}