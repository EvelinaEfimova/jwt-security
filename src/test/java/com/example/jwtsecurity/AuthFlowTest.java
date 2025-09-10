// src/test/java/com/example/jwtsecurity/AuthFlowTest.java
package com.example.jwtsecurity;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    @Test
    void register_login_refresh_ok() throws Exception {
        String email = "user+" + UUID.randomUUID() + "@example.com";

        String regJson = om.writeValueAsString(Map.of(
                "username", email,
                "password", "secret123",
                "role", "USER"
        ));
        MvcResult reg = mvc.perform(
                post("/api/auth/register").secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        String access1 = TestUtils.readAccessToken(reg.getResponse().getContentAsString());
        assertThat(access1).isNotBlank();

        String loginJson = om.writeValueAsString(Map.of(
                "username", email,
                "password", "secret123"
        ));
        MvcResult login = mvc.perform(
                post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        String refresh = TestUtils.readRefreshToken(login.getResponse().getContentAsString());
        assertThat(refresh).isNotBlank();

        String refreshJson = om.writeValueAsString(Map.of("refreshToken", refresh));
        mvc.perform(
                post("/api/auth/refresh").secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }
}
