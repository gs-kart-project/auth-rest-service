package com.gskart.user.DTOs.requests;

import com.gskart.user.DTOs.RoleDto;
import lombok.Data;

import java.util.Set;

@Data
public class ValidateTokenRequest {
    private String token;
    private String username;
    private Set<RoleDto> roles;
}
