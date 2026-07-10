package com.gskart.user.services;

import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.repositories.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Service
public class TokenCleanupService implements ITokenCleanupService {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public TokenCleanupService(RefreshTokenRepository refreshTokenRepository,
                                BlacklistedTokenRepository blacklistedTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.blacklistedTokenRepository = blacklistedTokenRepository;
    }

    @Override
    @Transactional
    @Scheduled(cron = "${gskart.jobs.token-cleanup.cron}", zone = "UTC")
    public void purgeExpiredTokens() {
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC);
        int refreshTokensDeleted = refreshTokenRepository.bulkDeleteExpiredBefore(cutoff);
        int blacklistedTokensDeleted = blacklistedTokenRepository.bulkDeleteExpiredBefore(cutoff);
        log.info("Token cleanup purged {} expired refresh tokens and {} expired blacklisted tokens",
                refreshTokensDeleted, blacklistedTokensDeleted);
    }
}
