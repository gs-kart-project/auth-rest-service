package com.gskart.user.DTOs.response;

import lombok.Data;

@Data
public class TokenResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    private long expiresIn;
    private String refreshToken;
}
