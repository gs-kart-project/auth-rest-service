package com.gskart.user.security;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class RestAuthenticationEntryPointTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailResponseWriter responseWriter = new ProblemDetailResponseWriter(objectMapper);
    private final RestAuthenticationEntryPoint entryPoint = new RestAuthenticationEntryPoint(responseWriter);

    @Test
    void commence_writes401ProblemDetailBody() throws Exception {
        HttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/userinfo");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException authException = new BadCredentialsException("no credentials");

        entryPoint.commence(request, response, authException);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(new MediaType(MediaType.APPLICATION_PROBLEM_JSON, StandardCharsets.UTF_8));

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("detail").asString()).isEqualTo("Authentication is required to access this resource.");
    }
}
