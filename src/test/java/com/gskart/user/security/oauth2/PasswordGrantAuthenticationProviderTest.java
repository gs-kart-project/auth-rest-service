package com.gskart.user.security.oauth2;

import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.security.models.GSKartUserDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordGrantAuthenticationProviderTest {

    private static final String USERNAME = "jane.doe";
    private static final String PASSWORD = "S3cret-passw0rd";

    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private OAuth2AuthorizationService authorizationService;
    @Mock
    private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    private PasswordGrantAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new PasswordGrantAuthenticationProvider(
                userDetailsService, bCryptPasswordEncoder, authorizationService, tokenGenerator);

        AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
                .issuer("http://localhost:4011")
                .build();
        AuthorizationServerContext context = mock(AuthorizationServerContext.class);
        // Only the token-issuing paths read the settings; the rejection tests never get that far.
        lenient().when(context.getAuthorizationServerSettings()).thenReturn(settings);
        AuthorizationServerContextHolder.setContext(context);
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
    }

    @Test
    void supportsOnlyThePasswordGrantToken() {
        assertThat(provider.supports(PasswordGrantAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(OAuth2ClientAuthenticationToken.class)).isFalse();
    }

    @Test
    void issuesTokensForValidCredentials() {
        stubUser(User.UserStatus.ACTIVE, User.CredentialsStatus.ACTIVE);
        stubTokenGenerator();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken)
                provider.authenticate(passwordAuthentication(testClient(), PASSWORD));

        assertThat(result.getAccessToken().getTokenValue()).isEqualTo("access-token-value");
        assertThat(result.getRefreshToken().getTokenValue()).isEqualTo("refresh-token-value");
        verify(authorizationService).save(any(OAuth2Authorization.class));
    }

    /**
     * The gate that keeps the password grant to the dedicated test client: a client that can
     * authenticate but isn't registered for the grant gets unauthorized_client, and no credential
     * check ever runs.
     */
    @Test
    void clientWithoutThePasswordGrantIsRejectedAsUnauthorizedClient() {
        RegisteredClient clientWithoutGrant = RegisteredClient.withId("portal-id")
                .clientId("gskart-portal")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:3000/callback")
                .build();

        assertThatThrownBy(() -> provider.authenticate(passwordAuthentication(clientWithoutGrant, PASSWORD)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> assertThat(((OAuth2AuthenticationException) thrown).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));

        verify(authorizationService, never()).save(any());
    }

    @Test
    void wrongPasswordIsRejectedAsInvalidGrant() {
        stubUser(User.UserStatus.ACTIVE, User.CredentialsStatus.ACTIVE);

        assertThatThrownBy(() -> provider.authenticate(passwordAuthentication(testClient(), "wrong-password")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> assertThat(((OAuth2AuthenticationException) thrown).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

        verify(authorizationService, never()).save(any());
    }

    @Test
    void unknownUserIsRejectedWithTheSameErrorAsAWrongPassword() {
        when(userDetailsService.loadUserByUsername(USERNAME)).thenThrow(new UsernameNotFoundException("nope"));

        assertThatThrownBy(() -> provider.authenticate(passwordAuthentication(testClient(), PASSWORD)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> {
                    OAuth2AuthenticationException exception = (OAuth2AuthenticationException) thrown;
                    assertThat(exception.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
                    // Must not hint that the account doesn't exist (account-enumeration guard).
                    assertThat(exception.getError().getDescription()).isEqualTo("Invalid username or password");
                });
    }

    @Test
    void inactiveAccountIsRejectedEvenWithTheRightPassword() {
        stubUser(User.UserStatus.LOCKED, User.CredentialsStatus.ACTIVE);

        assertThatThrownBy(() -> provider.authenticate(passwordAuthentication(testClient(), PASSWORD)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> assertThat(((OAuth2AuthenticationException) thrown).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

        verify(authorizationService, never()).save(any());
    }

    @Test
    void expiredCredentialsAreRejected() {
        stubUser(User.UserStatus.ACTIVE, User.CredentialsStatus.EXPIRED);

        assertThatThrownBy(() -> provider.authenticate(passwordAuthentication(testClient(), PASSWORD)))
                .isInstanceOf(OAuth2AuthenticationException.class);

        verify(authorizationService, never()).save(any());
    }

    @Test
    void unauthenticatedClientIsRejectedAsInvalidClient() {
        OAuth2ClientAuthenticationToken unauthenticatedClient = new OAuth2ClientAuthenticationToken(
                "gskart-test-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret", null);
        PasswordGrantAuthenticationToken authentication = new PasswordGrantAuthenticationToken(
                USERNAME, PASSWORD, unauthenticatedClient, Map.of());

        assertThatThrownBy(() -> provider.authenticate(authentication))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(thrown -> assertThat(((OAuth2AuthenticationException) thrown).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    private RegisteredClient testClient() {
        return RegisteredClient.withId("test-client-id")
                .clientId("gskart-test-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(PasswordGrantAuthenticationToken.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
    }

    private PasswordGrantAuthenticationToken passwordAuthentication(RegisteredClient registeredClient,
                                                                    String password) {
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
        clientPrincipal.setAuthenticated(true);
        return new PasswordGrantAuthenticationToken(USERNAME, password, clientPrincipal, Map.of());
    }

    private void stubUser(User.UserStatus userStatus, User.CredentialsStatus credentialsStatus) {
        Role developer = new Role();
        developer.setName("Developer");

        User user = new User();
        user.setUsername(USERNAME);
        user.setEmail("jane.doe@gskart.local");
        user.setPassword(bCryptPasswordEncoder.encode(PASSWORD));
        user.setRoles(Set.of(developer));
        user.setUserStatus(userStatus);
        user.setCredentialsStatus(credentialsStatus);

        when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(new GSKartUserDetails(user));
    }

    private void stubTokenGenerator() {
        Instant issuedAt = Instant.now();
        Jwt accessToken = Jwt.withTokenValue("access-token-value")
                .header("alg", "RS256")
                .claim("sub", USERNAME)
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(15, ChronoUnit.MINUTES))
                .build();
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token-value", issuedAt, issuedAt.plus(7, ChronoUnit.DAYS));

        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenAnswer(invocation -> {
            OAuth2TokenContext context = invocation.getArgument(0);
            return OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ? accessToken : refreshToken;
        });
    }
}
