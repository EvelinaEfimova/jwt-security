package com.example.jwtsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwtsecurity.dto.AuthResponse;
import com.example.jwtsecurity.dto.LoginRequest;
import com.example.jwtsecurity.dto.RefreshRequest;
import com.example.jwtsecurity.dto.RegisterRequest;
import com.example.jwtsecurity.entity.Role;
import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.service.OurUserDetailedService;
import com.example.jwtsecurity.service.UserService;
import com.example.jwtsecurity.util.JWTUtils;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final OurUserDetailedService uds;
    private final JWTUtils jwt;
    private final UserService userService;

    public AuthController(AuthenticationManager authManager,
                          OurUserDetailedService uds,
                          JWTUtils jwt,
                          UserService userService) {
        this.authManager = authManager;
        this.uds = uds;
        this.jwt = jwt;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        Role role = Role.USER;
        if (req.getRole() != null) {
            role = Role.valueOf(req.getRole());
        }
        User u = userService.register(req.getUsername(), req.getPassword(), role);
        String access = jwt.generateAccessToken(u);
        String refresh = jwt.generateRefreshToken(u);
        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));

        UserDetails user = uds.loadUserByUsername(req.getUsername());
        String access = jwt.generateAccessToken(user);
        String refresh = jwt.generateRefreshToken(user);
        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        String token = req.getRefreshToken();
        if (!jwt.isRefreshToken(token)) {
            return ResponseEntity.status(401).build();
        }
        String username = jwt.extractUsername(token);
        UserDetails user = uds.loadUserByUsername(username);
        if (!jwt.isTokenValid(token, user)) {
            return ResponseEntity.status(401).build();
        }
        String access = jwt.generateAccessToken(user);
        String refresh = jwt.generateRefreshToken(user);
        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }
}
