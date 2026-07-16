package com.gskart.user.security.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
 * Token endpoint request for the custom {@code password} grant (RFC 6749 §4.3). The grant is not
 * part of Spring Authorization Server; it exists only so curl and the integration tests can get a
 * token without driving a browser flow.
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    private final String username;
    private final String password;

    public PasswordGrantAuthenticationToken(String username, String password, Authentication clientPrincipal,
                                            Map<String, Object> additionalParameters) {
        super(PASSWORD, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
