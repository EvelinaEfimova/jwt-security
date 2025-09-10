package com.example.jwtsecurity.events;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.jwtsecurity.repo.UserRepository;

@Component
public class AuthFailureListener implements ApplicationListener<AbstractAuthenticationFailureEvent> {

    private final UserRepository repo;

    @Value("${app.security.max-failed-attempts}")
    private int maxFailed;

    @Value("${app.security.lock-duration-minutes}")
    private int lockMinutes;

    public AuthFailureListener(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
        Authentication auth = event.getAuthentication();
        String username = auth.getName();
        repo.findByUsername(username).ifPresent(u -> {
            u.refreshLockStatusIfExpired();
            if (u.isAccountNonLocked()) {
                u.increaseFailed();
                if (u.getFailedAttempts() >= maxFailed) {
                    u.lockForMinutes(lockMinutes);
                }
                repo.save(u);
            }
        });
    }
}
