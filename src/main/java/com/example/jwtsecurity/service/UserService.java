package com.example.jwtsecurity.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.jwtsecurity.entity.Role;
import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.repo.UserRepository;

@Service
public class UserService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public UserService(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Transactional
    public User register(String username, String rawPassword, Role role) {
        if (repo.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already used");
        }
        User u = new User(username, encoder.encode(rawPassword), role);
        return repo.save(u);
    }

    @Transactional
    public void unlockUser(String username) {
        repo.findByUsername(username).ifPresent(u -> {
            u.unlock();
            repo.save(u);
        });
    }
}
