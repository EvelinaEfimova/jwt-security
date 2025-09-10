package com.example.jwtsecurity.events;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import com.example.jwtsecurity.repo.UserRepository;

@Component
public class AuthSuccessListener implements ApplicationListener<AuthenticationSuccessEvent> {

    private final UserRepository repo;

    public AuthSuccessListener(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        repo.findByUsername(username).ifPresent(u -> {
            u.refreshLockStatusIfExpired();
            if (!u.isAccountNonLockedFlag()) {
                return;
            }
            u.resetFailed();
            repo.save(u);
        });
    }
}
