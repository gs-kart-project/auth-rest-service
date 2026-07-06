package com.gskart.user.DTOs.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenRequest {
    @NotBlank
    private String grantType;
    private String username;
    private String password;
    private String refreshToken;
}
