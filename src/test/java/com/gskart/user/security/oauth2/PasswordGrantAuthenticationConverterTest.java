package com.gskart.user.security.oauth2;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordGrantAuthenticationConverterTest {

    private final PasswordGrantAuthenticationConverter converter = new PasswordGrantAuthenticationConverter();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void convertsAPasswordGrantRequest() {
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal());
        MockHttpServletRequest request = passwordRequest();
        request.addParameter("scope", "openid");

        PasswordGrantAuthenticationToken authentication =
                (PasswordGrantAuthenticationToken) converter.convert(request);

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("jane.doe");
        assertThat(authentication.getPassword()).isEqualTo("S3cret-passw0rd");
        assertThat(authentication.getGrantType()).isEqualTo(PasswordGrantAuthenticationToken.PASSWORD);
        assertThat(authentication.getPrincipal()).isEqualTo(clientPrincipal());
        // grant_type/username/password are consumed; anything else rides along.
        assertThat(authentication.getAdditionalParameters()).containsExactly(java.util.Map.entry("scope", "openid"));
    }

    /** Other grants must fall through to the built-in SAS converters. */
    @Test
    void returnsNullForOtherGrantTypes() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "refresh_token");
        request.addParameter("refresh_token", "some-token");

        assertThat(converter.convert(request)).isNull();
    }

    @Test
    void returnsNullWhenGrantTypeIsAbsent() {
        assertThat(converter.convert(new MockHttpServletRequest())).isNull();
    }

    @Test
    void rejectsAMissingUsername() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "password");
        request.addParameter("password", "S3cret-passw0rd");

        assertInvalidRequest(request);
    }

    @Test
    void rejectsAMissingPassword() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "password");
        request.addParameter("username", "jane.doe");

        assertInvalidRequest(request);
    }

    /** A repeated credential parameter is ambiguous; RFC 6749 §3.1 says reject it. */
    @Test
    void rejectsARepeatedUsernameParameter() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "password");
        request.addParameter("username", "jane.doe", "someone.else");
        request.addParameter("password", "S3cret-passw0rd");

        assertInvalidRequest(request);
    }

    private void assertInvalidRequest(MockHttpServletRequest request) {
        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> assertThat(((OAuth2AuthenticationException) thrown).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    private MockHttpServletRequest passwordRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "password");
        request.addParameter("username", "jane.doe");
        request.addParameter("password", "S3cret-passw0rd");
        return request;
    }

    private Authentication clientPrincipal() {
        return new UsernamePasswordAuthenticationToken("gskart-test-client", null, List.of());
    }
}
