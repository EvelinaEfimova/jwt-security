package com.example.jwtsecurity;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LockoutTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    @BeforeEach
    @SuppressWarnings("unused")
    void registerUser() throws Exception {
        String reg = om.writeValueAsString(Map.of(
                "username", "lock@example.com",
                "password", "correctPass",
                "role", "USER"
        ));
        mvc.perform(post("/api/auth/register").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(reg))
                .andExpect(status().isOk());
    }

    @Test
    void locksAfterThreeBadAttempts_thenRejectsEvenCorrect() throws Exception {
        String badLogin = om.writeValueAsString(Map.of(
                "username", "lock@example.com",
                "password", "wrong1"
        ));
        mvc.perform(post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());

        String goodLogin = om.writeValueAsString(Map.of(
                "username", "lock@example.com",
                "password", "correctPass"
        ));
        mvc.perform(post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(goodLogin))
                .andExpect(status().isUnauthorized());
    }
}
