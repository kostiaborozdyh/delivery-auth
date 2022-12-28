package com.delivery.auth.config;

import com.delivery.auth.config.config.AppProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@EnableConfigurationProperties({AppProperties.class})
@ComponentScan(basePackages = "com.delivery.auth")
public class ApplicationConfig {
}
