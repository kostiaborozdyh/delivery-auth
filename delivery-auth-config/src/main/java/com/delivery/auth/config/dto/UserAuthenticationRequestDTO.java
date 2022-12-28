package com.delivery.auth.config.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class UserAuthenticationRequestDTO {
    private String username;
    private String password;
}
