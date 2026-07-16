package com.gskart.user.security.oauth2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Redirect-level checks on the authorization_code flow the portal will use. The portal is a public
 * client, so PKCE is mandatory — an authorization request without a challenge must not produce a
 * code.
 */
@SpringBootTest
class AuthorizationCodeFlowTest {

    private static final String REDIRECT_URI = "http://localhost:3000/callback";
    // S256 challenge for the verifier "gskart-test-code-verifier-0123456789012345678901234567890".
    private static final String CODE_CHALLENGE = "YjSTFhFDP1avMiDLXXJt9uFx_R6k50DNvFGPiREXEks";

    private MockMvc mockMvc;

    /**
     * Built by hand rather than with @AutoConfigureMockMvc: Boot 4 no longer auto-applies the
     * springSecurity() configurer, and without it @WithMockUser never reaches the filter chain.
     */
    @BeforeEach
    void setUp(WebApplicationContext webApplicationContext) {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .apply(springSecurity())
                .build();
    }

    @Test
    void unauthenticatedBrowserIsRedirectedToTheLoginForm() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .accept(MediaType.TEXT_HTML)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "gskart-portal")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid profile")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).endsWith("/login");
    }

    @Test
    @WithMockUser(username = "jane.doe")
    void authenticatedUserGetsAnAuthorizationCodeOnTheRedirectUri() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "gskart-portal")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid profile")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // No consent screen is configured, so the code comes straight back on the redirect.
        assertThat(result.getResponse().getRedirectedUrl())
                .startsWith(REDIRECT_URI)
                .contains("code=");
    }

    /** PKCE is required for the public portal client: no challenge, no code. */
    @Test
    @WithMockUser(username = "jane.doe")
    void authorizationRequestWithoutPkceIsRejected() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "gskart-portal")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("scope", "openid profile"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .contains("error=invalid_request")
                .doesNotContain("code=");
    }

    @Test
    @WithMockUser(username = "jane.doe")
    void authorizationRequestForAnUnregisteredRedirectUriIsRejected() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "gskart-portal")
                        .queryParam("redirect_uri", "http://evil.example.com/callback")
                        .queryParam("scope", "openid profile")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256"))
                // An unregistered redirect_uri must never be redirected to.
                .andExpect(status().isBadRequest());
    }
}
