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
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleAccessTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    String userToken;
    String moderatorToken;
    String adminToken;

    @BeforeEach
    @SuppressWarnings("unused")
    void setup() throws Exception {
        userToken = registerAndLogin("user@example.com", "USER");
        moderatorToken = registerAndLogin("mod@example.com", "MODERATOR");
        adminToken = registerAndLogin("admin@example.com", "SUPER_ADMIN");
    }

    private String registerAndLogin(String email, String role) throws Exception {
        String reg = om.writeValueAsString(Map.of("username", email, "password", "p@ssw0rd", "role", role));
        mvc.perform(post("/api/auth/register").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(reg))
                .andExpect(status().isOk());

        String login = om.writeValueAsString(Map.of("username", email, "password", "p@ssw0rd"));
        MvcResult res = mvc.perform(post("/api/auth/login").secure(true)
                        .contentType(MediaType.APPLICATION_JSON).content(login))
                .andExpect(status().isOk())
                .andReturn();
        return TestUtils.readAccessToken(res.getResponse().getContentAsString());
    }

    @Test
    void user_access() throws Exception {
        mvc.perform(get("/api/demo/public").secure(true))
                .andExpect(status().isOk());

        mvc.perform(get("/api/demo/user").secure(true)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        mvc.perform(get("/api/demo/moderator").secure(true)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/demo/admin").secure(true)
                        .header("Authorization", "Bearer " + moderatorToken))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/demo/admin").secure(true)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }
}
