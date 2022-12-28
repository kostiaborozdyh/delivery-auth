package com.delivery.auth.config.service;

import com.delivery.auth.config.util.AuthUtil;
import com.delivery.db.entities.User;
import com.delivery.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserLoginService implements UserDetailsService {

    private static final String USER_NOT_FOUND_ERROR_MESSAGE = "User '%s' not found";

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> {
                    log.error(String.format(USER_NOT_FOUND_ERROR_MESSAGE, login));
                    return new UsernameNotFoundException(String.format(USER_NOT_FOUND_ERROR_MESSAGE, login));
                });

        return AuthUtil.createUserDetails(user);
    }
}
