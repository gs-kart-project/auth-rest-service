package com.gskart.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.repositories.RoleRepository;
import com.gskart.user.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Set;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The /api/v1 chain after the switch to bearer tokens. The point of these tests is that the flat
 * "roles" claim still drives @PreAuthorize("hasAuthority('Developer')") — a real token issued by
 * this server must open the same doors the hand-rolled JWT used to.
 */
@SpringBootTest
@ActiveProfiles("dev")
class ApiSecurityIntegrationTest {

    private static final String TEST_CLIENT = "gskart-test-client";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String DEVELOPER_USERNAME = "jane.doe";
    private static final String PLAIN_USERNAME = "john.plain";
    private static final String PASSWORD = "S3cret-passw0rd";

    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp(WebApplicationContext webApplicationContext) {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .apply(springSecurity())
                .build();

        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role developer = new Role();
        developer.setName("Developer");
        developer.setDescription("Developer role");
        saveUser(DEVELOPER_USERNAME, "jane.doe@gskart.local", Set.of(developer));
        saveUser(PLAIN_USERNAME, "john.plain@gskart.local", Set.of());
    }

    @Test
    void developerTokenIssuedByThisServerCanReachAProtectedEndpoint() throws Exception {
        String accessToken = obtainAccessToken(DEVELOPER_USERNAME);

        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }

    /** The roles claim is the only thing granting access; a user without it must be refused. */
    @Test
    void tokenWithoutTheDeveloperRoleIsForbidden() throws Exception {
        String accessToken = obtainAccessToken(PLAIN_USERNAME);

        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestWithoutATokenIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/roles"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void garbageBearerTokenIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }

    /** Registration has to stay open — it is how a user gets credentials in the first place. */
    @Test
    void userRegistrationRemainsPublic() throws Exception {
        String body = """
                {"firstname":"New","lastname":"User","email":"new.user@gskart.local",
                 "username":"new.user","password":"An0ther-passw0rd"}
                """;

        mockMvc.perform(post("/api/v1/users")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    void actuatorHealthRemainsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    /** Authorities come from the claim, not from a database lookup at request time. */
    @Test
    void authoritiesAreMappedFromTheRolesClaim() throws Exception {
        mockMvc.perform(get("/api/v1/roles").with(jwt().authorities(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("Developer"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/roles").with(jwt()))
                .andExpect(status().isForbidden());
    }

    private void saveUser(String username, String email, Set<Role> roles) {
        User user = new User();
        user.setFirstname("Test");
        user.setLastname("User");
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(bCryptPasswordEncoder.encode(PASSWORD));
        user.setRoles(roles);
        user.setUserStatus(User.UserStatus.ACTIVE);
        user.setCredentialsStatus(User.CredentialsStatus.ACTIVE);
        userRepository.save(user);
    }

    private String obtainAccessToken(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TEST_CLIENT, TEST_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", username)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }
}
