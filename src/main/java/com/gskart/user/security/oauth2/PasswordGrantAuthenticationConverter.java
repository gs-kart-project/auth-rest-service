package com.gskart.user.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns a form-encoded {@code grant_type=password&username=&password=} token request into a
 * {@link PasswordGrantAuthenticationToken}. Returns null for any other grant so the built-in SAS
 * converters get their turn.
 */
public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    // Spring Security 7 dropped the resource-owner-password grant, and OAuth2ParameterNames no
    // longer carries these; they are still the RFC 6749 §4.3.2 parameter names.
    static final String USERNAME = "username";
    static final String PASSWORD = "password";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!PasswordGrantAuthenticationToken.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);

        String username = parameters.getFirst(USERNAME);
        if (!StringUtils.hasText(username) || parameters.get(USERNAME).size() != 1) {
            throw invalidRequest(USERNAME);
        }

        String password = parameters.getFirst(PASSWORD);
        if (!StringUtils.hasText(password) || parameters.get(PASSWORD).size() != 1) {
            throw invalidRequest(PASSWORD);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                    && !key.equals(USERNAME)
                    && !key.equals(PASSWORD)) {
                additionalParameters.put(key, values.size() == 1 ? values.getFirst() : values.toArray(new String[0]));
            }
        });

        // The client authentication filter has already run, so this is the authenticated client.
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        return new PasswordGrantAuthenticationToken(username, password, clientPrincipal, additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> parameters.addAll(key, List.of(values)));
        return parameters;
    }

    private static OAuth2AuthenticationException invalidRequest(String parameterName) {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                "Missing or repeated parameter: " + parameterName,
                "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        return new OAuth2AuthenticationException(error);
    }
}
