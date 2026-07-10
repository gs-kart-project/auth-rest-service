package com.gskart.user.services;

import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.repositories.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenCleanupServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;

    private TokenCleanupService tokenCleanupService;

    @BeforeEach
    void setUp() {
        tokenCleanupService = new TokenCleanupService(refreshTokenRepository, blacklistedTokenRepository);
    }

    @Test
    void purgeExpiredTokens_deletesExpiredRowsFromBothRepositoriesUsingTheSameCutoff() {
        when(refreshTokenRepository.bulkDeleteExpiredBefore(any())).thenReturn(3);
        when(blacklistedTokenRepository.bulkDeleteExpiredBefore(any())).thenReturn(2);

        tokenCleanupService.purgeExpiredTokens();

        ArgumentCaptor<OffsetDateTime> refreshCutoff = ArgumentCaptor.forClass(OffsetDateTime.class);
        ArgumentCaptor<OffsetDateTime> blacklistedCutoff = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(refreshTokenRepository).bulkDeleteExpiredBefore(refreshCutoff.capture());
        verify(blacklistedTokenRepository).bulkDeleteExpiredBefore(blacklistedCutoff.capture());

        assertThat(refreshCutoff.getValue()).isCloseTo(OffsetDateTime.now(), within(5, ChronoUnit.SECONDS));
        assertThat(blacklistedCutoff.getValue()).isCloseTo(OffsetDateTime.now(), within(5, ChronoUnit.SECONDS));
    }
}
