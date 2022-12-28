package com.delivery.auth.config.util;

import com.delivery.auth.config.exception.FailedAuthenticationException;
import com.delivery.db.entities.User;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import lombok.experimental.UtilityClass;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

@UtilityClass
public final class AuthUtil {

    private static final String ROLE = "ROLE_";

    public String getCurrentUserLogin() {
        if (Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
            throw new FailedAuthenticationException("Login is null");
        }

        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    public UserDetails createUserDetails(User user) {
        Set<GrantedAuthority> authorities = getGrantedAuthorities(user);

        return new org.springframework.security.core.userdetails.User(user.getLogin(), user.getPassword(),
                true, true, true, !user.getBan(), authorities);
    }

    public List<GrantedAuthority> getGrantedAuthoritiesOfUser(User user) {
        return new ArrayList<>(getGrantedAuthorities(user));
    }

    private Set<GrantedAuthority> getGrantedAuthorities(User user) {
        return Collections.singleton(new SimpleGrantedAuthority(ROLE + user.getRole()));
    }
}
