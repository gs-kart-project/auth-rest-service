package com.gskart.user.utils;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.exceptions.JwtNotValidException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtHelperTest {

    private static final String ISSUER = "http://localhost:4011";

    private JwtHelper jwtHelper;
    private GskartKeystore gskartKeystore;

    @BeforeEach
    void setUp() {
        gskartKeystore = new GskartKeystore();
        ReflectionTestUtils.setField(gskartKeystore, "keystoreFilePath", "static/jwtKeys/gskartJwtKeystore.jks");
        ReflectionTestUtils.setField(gskartKeystore, "keystorePassword", "Gsk-jwt-key-202404");
        ReflectionTestUtils.setField(gskartKeystore, "keyPairAlias", "gskartJwtKeyPair");

        jwtHelper = new JwtHelper(gskartKeystore);
        ReflectionTestUtils.setField(jwtHelper, "accessTokenExpiryMinutes", 20L);
        ReflectionTestUtils.setField(jwtHelper, "issuer", ISSUER);
    }

    @Test
    void generateAndParseToken_roundTripsSubjectEmailRolesIssuerAndAudience() throws Exception {
        RoleDto role = new RoleDto();
        role.setName("USER");

        String token = jwtHelper.generateToken("jdoe", "jdoe@example.com", Set.of(role));
        Claims claims = jwtHelper.getClaimsFromToken(token);

        assertThat(claims.getSubject()).isEqualTo("jdoe");
        assertThat(claims.get("email")).isEqualTo("jdoe@example.com");
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getAudience()).contains(ISSUER);
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    void getClaimsFromToken_throwsJwtNotValidException_whenTokenIsExpired() throws Exception {
        ReflectionTestUtils.setField(jwtHelper, "accessTokenExpiryMinutes", -1L);
        String expiredToken = jwtHelper.generateToken("jdoe", "jdoe@example.com", Set.of());

        assertThatThrownBy(() -> jwtHelper.getClaimsFromToken(expiredToken))
                .isInstanceOf(JwtNotValidException.class);
    }

    @Test
    void getClaimsFromToken_throwsJwtNotValidException_whenTokenIsMalformed() {
        assertThatThrownBy(() -> jwtHelper.getClaimsFromToken("not-a-jwt"))
                .isInstanceOf(JwtNotValidException.class);
    }

    @Test
    void getClaimsFromToken_throwsJwtNotValidException_whenIssuerDoesNotMatch() throws Exception {
        Instant now = Instant.now();
        String tokenFromAnotherIssuer = Jwts.builder()
                .subject("jdoe")
                .id(UUID.randomUUID().toString())
                .issuer("http://imposter-issuer")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(20, ChronoUnit.MINUTES)))
                .signWith(gskartKeystore.readPrivateKey())
                .compact();

        assertThatThrownBy(() -> jwtHelper.getClaimsFromToken(tokenFromAnotherIssuer))
                .isInstanceOf(JwtNotValidException.class);
    }
}
