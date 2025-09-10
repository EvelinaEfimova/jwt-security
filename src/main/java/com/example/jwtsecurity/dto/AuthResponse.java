package com.example.jwtsecurity.dto;

public class AuthResponse {
    private String accessToken;
    private String refreshToken;

    public AuthResponse() {}
    public AuthResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String a) { this.accessToken = a; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String r) { this.refreshToken = r; }
}
