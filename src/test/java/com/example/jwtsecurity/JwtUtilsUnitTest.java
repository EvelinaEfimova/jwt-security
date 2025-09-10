package com.example.jwtsecurity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.example.jwtsecurity.util.JWTUtils;

@SpringBootTest
class JwtUtilsUnitTest {

    @Autowired
    private JWTUtils jwtUtils;

    @Test
    void generate_and_validate_token() {
        User user = new User("u@e.com", "pwd",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        String token = jwtUtils.generateAccessToken(user);
        assertThat(token).isNotBlank();

        String username = jwtUtils.extractUsername(token);
        assertThat(username).isEqualTo("u@e.com");
        assertThat(jwtUtils.isTokenValid(token, user)).isTrue();
    }
}
