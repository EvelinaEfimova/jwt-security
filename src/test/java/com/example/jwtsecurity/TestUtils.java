package com.example.jwtsecurity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TestUtils {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static String readAccessToken(String json) throws Exception {
        JsonNode node = MAPPER.readTree(json);
        return node.get("accessToken").asText();
    }
    public static String readRefreshToken(String json) throws Exception {
        JsonNode node = MAPPER.readTree(json);
        return node.get("refreshToken").asText();
    }
}
