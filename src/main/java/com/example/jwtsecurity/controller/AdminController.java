package com.example.jwtsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwtsecurity.service.UserService;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService users;

    public AdminController(UserService users) {
        this.users = users;
    }

    @PostMapping("/unlock/{username}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public String unlock(@PathVariable String username) {
        users.unlockUser(username);
        return "Unlocked: " + username;
    }
}
