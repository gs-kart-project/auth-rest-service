package com.gskart.user.repositories;

import com.gskart.user.entities.BlacklistedToken;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class BlacklistedTokenRepositoryTest {

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Autowired
    private EntityManager entityManager;

    private BlacklistedToken buildToken(String tokenId, OffsetDateTime expiresOn) {
        BlacklistedToken blacklistedToken = new BlacklistedToken();
        blacklistedToken.setTokenId(tokenId);
        blacklistedToken.setExpiresOn(expiresOn);
        blacklistedToken.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        blacklistedToken.setCreatedBy("jdoe");
        return blacklistedToken;
    }

    @Test
    void bulkDeleteExpiredBefore_removesOnlyExpiredTokens() {
        blacklistedTokenRepository.save(buildToken("expired-jti", OffsetDateTime.now(ZoneOffset.UTC).minusDays(1)));
        blacklistedTokenRepository.save(buildToken("active-jti", OffsetDateTime.now(ZoneOffset.UTC).plusDays(1)));

        int deleted = blacklistedTokenRepository.bulkDeleteExpiredBefore(OffsetDateTime.now(ZoneOffset.UTC));
        entityManager.clear();

        assertThat(deleted).isEqualTo(1);
        assertThat(blacklistedTokenRepository.existsByTokenId("expired-jti")).isFalse();
        assertThat(blacklistedTokenRepository.existsByTokenId("active-jti")).isTrue();
    }
}
