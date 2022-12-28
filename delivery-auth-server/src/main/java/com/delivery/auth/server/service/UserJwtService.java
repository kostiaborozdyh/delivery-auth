package com.delivery.auth.server.service;

import com.delivery.auth.config.exception.BadRequestException;
import com.delivery.auth.config.util.AuthUtil;
import com.delivery.db.entities.User;
import com.delivery.db.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserJwtService {

    private final UserRepository userRepository;

    public List<GrantedAuthority> getUserAuthorities(String username) {
        User user = userRepository.findByLogin(username)
                .orElseThrow(() -> new BadRequestException("No user with this login"));

        return AuthUtil.getGrantedAuthoritiesOfUser(user);
    }
}
