package com.example.jwtsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Hello, public!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','MODERATOR','SUPER_ADMIN')")
    public String userEndpoint() {
        return "Hello, user!";
    }

    @GetMapping("/moderator")
    @PreAuthorize("hasAnyRole('MODERATOR','SUPER_ADMIN')")
    public String moderatorEndpoint() {
        return "Hello, moderator!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public String adminEndpoint() {
        return "Hello, super admin!";
    }
}
