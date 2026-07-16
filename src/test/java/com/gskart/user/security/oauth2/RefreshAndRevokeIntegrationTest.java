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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Refresh tokens are the revocable half of the design (access tokens are short-lived and not
 * revocable), so rotation and revocation are what actually bound a compromised session.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RefreshAndRevokeIntegrationTest {

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
    void refreshTokenGrantIssuesANewAccessToken() throws Exception {
        String refreshToken = obtainRefreshToken();

        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists());
    }

    /** reuseRefreshTokens(false): the old token must die the moment it is exchanged. */
    @Test
    void usedRefreshTokenIsRejectedAfterRotation() throws Exception {
        String refreshToken = obtainRefreshToken();

        MvcResult rotated = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andReturn();

        String rotatedRefreshToken = objectMapper.readTree(rotated.getResponse().getContentAsString())
                .get("refresh_token").asText();
        assertThat(rotatedRefreshToken).isNotEqualTo(refreshToken);

        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void revokedRefreshTokenCanNoLongerBeExchanged() throws Exception {
        String refreshToken = obtainRefreshToken();

        mockMvc.perform(post("/oauth2/revoke")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("token", refreshToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    private String obtainRefreshToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", USERNAME)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        return response.get("refresh_token").asText();
    }
}
