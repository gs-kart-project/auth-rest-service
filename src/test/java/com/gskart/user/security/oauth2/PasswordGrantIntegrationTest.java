package com.gskart.user.security.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.repositories.RoleRepository;
import com.gskart.user.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The password grant is the path curl and the tests use to get a token. These tests pin both that
 * it works for the dedicated test client and that it is unavailable to anyone else.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class PasswordGrantIntegrationTest {

    private static final String TEST_CLIENT = "gskart-test-client";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String USERNAME = "jane.doe";
    private static final String PASSWORD = "S3cret-passw0rd";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private JwtDecoder jwtDecoder;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role developer = new Role();
        developer.setName("Developer");
        developer.setDescription("Developer role");

        User user = new User();
        user.setFirstname("Jane");
        user.setLastname("Doe");
        user.setEmail("jane.doe@gskart.local");
        user.setUsername(USERNAME);
        user.setPassword(bCryptPasswordEncoder.encode(PASSWORD));
        user.setRoles(Set.of(developer));
        user.setUserStatus(User.UserStatus.ACTIVE);
        user.setCredentialsStatus(User.CredentialsStatus.ACTIVE);
        userRepository.save(user);
    }

    @Test
    void passwordGrantIssuesAccessTokenWithGskartClaims() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        Jwt accessToken = jwtDecoder.decode(response.get("access_token").asText());

        assertThat(accessToken.getSubject()).isEqualTo(USERNAME);
        assertThat(accessToken.getIssuer()).hasToString("http://localhost:4011");
        assertThat(accessToken.getClaimAsString("email")).isEqualTo("jane.doe@gskart.local");
        assertThat(accessToken.getClaimAsStringList("roles")).containsExactly("Developer");

        Duration lifetime = Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt());
        assertThat(lifetime).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void accessTokenIsSignedWithTheGskartKeyId() throws Exception {
        String accessToken = obtainAccessToken();

        Jwt jwt = jwtDecoder.decode(accessToken);
        assertThat(jwt.getHeaders()).containsEntry("kid", "gskart-jwt-key");
    }

    @Test
    void badPasswordIsRejectedAsInvalidGrant() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", "not-the-password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void unknownUserIsRejectedAsInvalidGrant() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", "no.such.user")
                        .param("password", PASSWORD))
                .andExpect(status().isBadRequest())
                // Same error as a bad password: a caller must not be able to enumerate accounts.
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    /**
     * The point of the whole profile-gated-client design: only the test client holds this grant.
     * Portal is a public client, so it never authenticates for a password request at all (SAS only
     * authenticates public clients for authorization_code+PKCE, which supplies a code_verifier) and
     * the request is rejected before the grant-type check is reached. The grant-type gate that
     * backs this up for a client that *can* authenticate is covered in
     * PasswordGrantAuthenticationProviderTest.
     */
    @Test
    void portalClientCannotUseThePasswordGrant() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .param("client_id", "gskart-portal")
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain("access_token");
    }

    @Test
    void tokenRequestWithoutClientAuthenticationIsRejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missingPasswordParameterIsRejectedAsInvalidRequest() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", USERNAME))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    private String obtainAccessToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }
}
