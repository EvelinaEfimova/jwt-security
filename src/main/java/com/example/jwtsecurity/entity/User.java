package com.example.jwtsecurity.entity;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email @NotBlank
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank @Size(min = 6)
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    private boolean accountNonLocked = true;
    private int failedAttempts = 0;
    private Instant lockUntil;

    public User() {}

    public User(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public Long getId() { return id; }
    @Override
    public String getUsername() { return username; }
    public void setUsername(String u) { this.username = u; }
    @Override public String getPassword() { return password; }
    public void setPassword(String p) { this.password = p; }
    public Role getRole() { return role; }
    public void setRole(Role r) { this.role = r; }

    public boolean isAccountNonLockedFlag() { return accountNonLocked; }
    public void setAccountNonLocked(boolean v) { this.accountNonLocked = v; }
    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int v) { this.failedAttempts = v; }
    public Instant getLockUntil() { return lockUntil; }
    public void setLockUntil(Instant lockUntil) { this.lockUntil = lockUntil; }

    public void increaseFailed() { this.failedAttempts++; }
    public void resetFailed() { this.failedAttempts = 0; }
    public void lockForMinutes(int minutes) {
        this.accountNonLocked = false;
        this.lockUntil = Instant.now().plus(minutes, ChronoUnit.MINUTES);
    }
    public void unlock() {
        this.accountNonLocked = true;
        this.lockUntil = null;
        this.failedAttempts = 0;
    }
    public void refreshLockStatusIfExpired() {
        if (!accountNonLocked && lockUntil != null && Instant.now().isAfter(lockUntil)) {
            unlock();
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.asAuthority()));
    }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() {
        refreshLockStatusIfExpired();
        return accountNonLocked;
    }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
