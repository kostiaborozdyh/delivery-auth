package com.delivery.auth.config.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
@Getter
@Setter
public class AppProperties {
    private String tokenSecret;
    private long tokenExpirationMsec;
    private long tokenRefreshExpirationMsec;
}
