package com.gskart.user.DTOs.response;

import com.gskart.user.DTOs.UserDto;
import lombok.Data;

@Data
public class LoginResponse {
    private UserDto user;
    private String refreshToken;
}
