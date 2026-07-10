package com.gskart.user.repositories;

import com.gskart.user.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUsernameAndRevokedFalse(String username);

    /**
     * Atomically revokes the token only if it is still active. Returns the number of rows
     * updated (0 or 1) so callers can detect a concurrent rotation/replay attempt.
     */
    @Modifying
    @Query("update refresh_tokens t set t.revoked = true where t.token = :token and t.revoked = false")
    int revokeIfActive(@Param("token") String token);

    @Modifying
    @Query("delete from refresh_tokens t where t.expiresOn < :cutoff")
    int bulkDeleteExpiredBefore(@Param("cutoff") OffsetDateTime cutoff);
}
