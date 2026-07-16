package com.gskart.user.security;

import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.security.jackson.GskartRoleMixin;
import com.gskart.user.security.jackson.GskartUserDetailsMixin;
import com.gskart.user.security.jackson.RoleMixin;
import com.gskart.user.security.jackson.UserMixin;
import com.gskart.user.security.models.GSKartRole;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.security.oauth2.PasswordGrantAuthenticationToken;
import com.gskart.user.utils.IGskartKeystore;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;

/**
 * Spring Authorization Server wiring: registered clients, signing keys and the token pipeline.
 * Endpoints stay on the SAS defaults (/oauth2/token, /oauth2/jwks, /.well-known/...) so they line
 * up with the bare issuer that resource servers use for discovery.
 */
@Configuration
public class AuthorizationServerConfig {

    /** Published in the JWKS and in every token header, so resource servers can select the key. */
    public static final String SIGNING_KEY_ID = "gskart-jwt-key";

    /** Fixed so authorization rows written by a previous run still resolve after a restart. */
    private static final String PORTAL_CLIENT_ID = "3f1b2c4e-8a5d-4c7b-9e6f-1a2b3c4d5e6f";
    private static final String TEST_CLIENT_ID = "7c9e6b1a-2d3f-4a5b-8c7d-9e0f1a2b3c4d";

    private final IGskartKeystore gskartKeystore;

    @Value("${gskart.jwt.access-token.expiry-minutes}")
    private long accessTokenExpiryMinutes;

    @Value("${gskart.jwt.refresh-token.expiry-days}")
    private long refreshTokenExpiryDays;

    @Value("${gskart.oauth2.portal-client.redirect-uri}")
    private String portalRedirectUri;

    public AuthorizationServerConfig(IGskartKeystore gskartKeystore) {
        this.gskartKeystore = gskartKeystore;
    }

    @Bean
    public RegisteredClient portalClient() {
        return RegisteredClient.withId(PORTAL_CLIENT_ID)
                .clientId("gskart-portal")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(portalRedirectUri)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(tokenSettings())
                .build();
    }

    /**
     * Sole holder of the password grant, and only registered under local/dev — the grant does not
     * exist in prod. Any other client asking for grant_type=password is rejected as
     * unauthorized_client because the grant isn't in its registration.
     */
    @Bean
    @Profile({"local", "dev"})
    public RegisteredClient testClient(@Value("${gskart.oauth2.test-client.secret}") String testClientSecret,
                                       BCryptPasswordEncoder bCryptPasswordEncoder) {
        return RegisteredClient.withId(TEST_CLIENT_ID)
                .clientId("gskart-test-client")
                .clientSecret(bCryptPasswordEncoder.encode(testClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(PasswordGrantAuthenticationToken.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSettings())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(List<RegisteredClient> registeredClients) {
        return new InMemoryRegisteredClientRepository(registeredClients);
    }

    /**
     * JDBC-backed so refresh tokens survive a restart and stay revocable, matching the guarantee
     * the old refresh_tokens table gave.
     *
     * The mappers get a JsonMapper that knows our principal types. Without it the authorization row
     * is written fine but cannot be read back: the stored principal is a GSKartUserDetails, and
     * Jackson's polymorphic type validator rejects any type it hasn't been told to trust, which
     * breaks every refresh_token exchange.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
                                                           RegisteredClientRepository registeredClientRepository) {
        JsonMapper jsonMapper = authorizationJsonMapper();

        JdbcOAuth2AuthorizationService authorizationService =
                new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
        authorizationService.setAuthorizationRowMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(
                        registeredClientRepository, jsonMapper));
        authorizationService.setAuthorizationParametersMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper));
        return authorizationService;
    }

    private JsonMapper authorizationJsonMapper() {
        ClassLoader classLoader = AuthorizationServerConfig.class.getClassLoader();
        BasicPolymorphicTypeValidator.Builder typeValidator = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.gskart.user.");

        return JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(classLoader, typeValidator))
                .addModule(new OAuth2AuthorizationServerJacksonModule())
                .addMixIn(GSKartUserDetails.class, GskartUserDetailsMixin.class)
                .addMixIn(GSKartRole.class, GskartRoleMixin.class)
                .addMixIn(User.class, UserMixin.class)
                .addMixIn(Role.class, RoleMixin.class)
                .build();
    }

    /**
     * Endpoint paths stay on the SAS defaults; only the issuer is pinned. It has to be set here
     * because declaring this bean makes Boot's authorization-server autoconfiguration back off,
     * which would otherwise leave the issuer derived from the request host.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${spring.security.oauth2.authorizationserver.issuer}") String issuer) {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    /** Reuses the existing JKS keypair, so tokens signed before this change still verify. */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws JwtKeyStoreException {
        RSAPublicKey publicKey;
        RSAPrivateKey privateKey;
        try {
            publicKey = gskartKeystore.readPublicKey();
            privateKey = gskartKeystore.readPrivateKey();
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException
                 | UnrecoverableKeyException e) {
            throw new JwtKeyStoreException("Unable to build the JWK source from the Gskart keystore.", e);
        }

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(SIGNING_KEY_ID)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Declared explicitly because the password grant provider needs the same generator SAS uses;
     * without this bean it would only exist inside the authorization server configurer.
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
                                                  OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(tokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2RefreshTokenGenerator());
    }

    private TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(accessTokenExpiryMinutes))
                .refreshTokenTimeToLive(Duration.ofDays(refreshTokenExpiryDays))
                .reuseRefreshTokens(false)
                .build();
    }
}
