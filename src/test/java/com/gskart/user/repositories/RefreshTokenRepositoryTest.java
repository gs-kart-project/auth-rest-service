package com.gskart.user.repositories;

import com.gskart.user.entities.RefreshToken;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private EntityManager entityManager;

    private RefreshToken buildToken(String token, String username, boolean revoked) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUsername(username);
        refreshToken.setRevoked(revoked);
        refreshToken.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
        refreshToken.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        refreshToken.setCreatedBy(username);
        return refreshToken;
    }

    @Test
    void findByToken_returnsToken_whenItExists() {
        refreshTokenRepository.save(buildToken("token-1", "jdoe", false));

        Optional<RefreshToken> found = refreshTokenRepository.findByToken("token-1");

        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("jdoe");
    }

    @Test
    void findByUsernameAndRevokedFalse_excludesRevokedTokens() {
        refreshTokenRepository.save(buildToken("active-token", "jdoe", false));
        refreshTokenRepository.save(buildToken("revoked-token", "jdoe", true));

        List<RefreshToken> activeTokens = refreshTokenRepository.findByUsernameAndRevokedFalse("jdoe");

        assertThat(activeTokens).extracting(RefreshToken::getToken).containsExactly("active-token");
    }

    @Test
    void revokeIfActive_revokesAndReturnsOne_whenTokenIsActive() {
        refreshTokenRepository.save(buildToken("active-token", "jdoe", false));

        int updated = refreshTokenRepository.revokeIfActive("active-token");
        entityManager.clear();

        assertThat(updated).isEqualTo(1);
        assertThat(refreshTokenRepository.findByToken("active-token").get().isRevoked()).isTrue();
    }

    @Test
    void revokeIfActive_returnsZero_whenTokenIsAlreadyRevoked() {
        refreshTokenRepository.save(buildToken("revoked-token", "jdoe", true));

        int updated = refreshTokenRepository.revokeIfActive("revoked-token");

        assertThat(updated).isEqualTo(0);
    }

    @Test
    void bulkDeleteExpiredBefore_removesOnlyExpiredTokens() {
        RefreshToken expired = buildToken("expired-token", "jdoe", false);
        expired.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).minusDays(1));
        refreshTokenRepository.save(expired);
        refreshTokenRepository.save(buildToken("active-token", "jdoe", false));

        int deleted = refreshTokenRepository.bulkDeleteExpiredBefore(OffsetDateTime.now(ZoneOffset.UTC));
        entityManager.clear();

        assertThat(deleted).isEqualTo(1);
        assertThat(refreshTokenRepository.findByToken("expired-token")).isEmpty();
        assertThat(refreshTokenRepository.findByToken("active-token")).isPresent();
    }
}
