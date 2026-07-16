-- Supports the daily TokenCleanupService purge (WHERE expires_on < :cutoff), which was doing an
-- unindexed full-table scan on both token tables.
create index IDX_RefreshTokens_ExpiresOn on refresh_tokens (expires_on);

create index IDX_BlacklistedTokens_ExpiresOn on blacklisted_tokens (expires_on);
