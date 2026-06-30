package com.gskart.user.entities;

import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;

@Getter
@Setter
@Entity(name = "refresh_tokens")
public class RefreshToken extends BaseEntity {
    private String token;
    private String username;
    private OffsetDateTime expiresOn;
    private boolean revoked;
}
