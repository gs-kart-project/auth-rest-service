package com.gskart.user.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class ProblemDetailResponseWriterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailResponseWriter writer = new ProblemDetailResponseWriter(objectMapper);

    @Test
    void write_setsStatusContentTypeAndProblemDetailBody() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        writer.write(response, HttpStatus.UNAUTHORIZED, "Invalid or expired authentication token.");

        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(new MediaType(MediaType.APPLICATION_PROBLEM_JSON, StandardCharsets.UTF_8));

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("detail").asString()).isEqualTo("Invalid or expired authentication token.");
    }
}
