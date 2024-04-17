package com.gskart.user.DTOs.response;

import com.gskart.user.DTOs.RoleDto;
import lombok.Data;

import java.util.Set;

@Data
public class ClaimsResponse {
    private String username;
    private String email;
    private Set<RoleDto> roles;
}
