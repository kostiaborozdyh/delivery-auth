package com.delivery.auth.config.security;

import com.delivery.auth.config.filter.JwtRequestFilter;
import com.delivery.auth.config.filter.JwtUsernameAndPasswordAuthenticationFilter;
import com.delivery.auth.config.filter.RestAuthenticationEntryPoint;
import com.delivery.auth.config.service.TokenProvider;
import com.delivery.auth.config.service.UserLoginService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserLoginService userLoginService;
    private final JwtRequestFilter jwtRequestFilter;
    private final ObjectMapper objectMapper;
    private final TokenProvider tokenProvider;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userLoginService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .httpBasic()
                    .disable()
                .formLogin()
                    .disable()
                .authorizeRequests()
                    .antMatchers("/refreshToken", "/review/all").permitAll()
                    .antMatchers("/check").hasAnyRole("ADMIN","USER","MANAGER","EMPLOYEE")
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**", "/order/**", "/review/**").hasRole("USER")
                    .antMatchers("/manager/**").hasRole("MANAGER")
                    .antMatchers("/employee/**").hasRole("EMPLOYEE")
                .and()
                .logout()
                    .logoutUrl("/logoutUser")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                .and()
                .exceptionHandling()
                    .authenticationEntryPoint(new RestAuthenticationEntryPoint());

        JwtUsernameAndPasswordAuthenticationFilter authorizationFilter =
                new JwtUsernameAndPasswordAuthenticationFilter(authenticationManagerBean(), tokenProvider, objectMapper);

        http
                .addFilter(authorizationFilter)
                .addFilterAfter(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
}