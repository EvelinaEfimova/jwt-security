package com.example.jwtsecurity.entity;

public enum Role {
    USER, MODERATOR, SUPER_ADMIN;

    public String asAuthority() {
        return "ROLE_" + name();
    }
}
