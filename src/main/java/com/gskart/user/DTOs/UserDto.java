package com.gskart.user.DTOs;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UserDto {
    @NotBlank
    private String username;
    private Set<RoleDto> roles;
}
