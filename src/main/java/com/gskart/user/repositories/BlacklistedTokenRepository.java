package com.gskart.user.repositories;

import com.gskart.user.entities.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {

    boolean existsByTokenId(String tokenId);

    @Modifying
    @Query("delete from blacklisted_tokens t where t.expiresOn < :cutoff")
    int bulkDeleteExpiredBefore(@Param("cutoff") OffsetDateTime cutoff);
}
