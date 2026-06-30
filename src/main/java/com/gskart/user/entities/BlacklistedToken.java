package com.gskart.user.entities;

import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;

@Getter
@Setter
@Entity(name = "blacklisted_tokens")
public class BlacklistedToken extends BaseEntity {
    private String tokenId;
    private OffsetDateTime expiresOn;
}
