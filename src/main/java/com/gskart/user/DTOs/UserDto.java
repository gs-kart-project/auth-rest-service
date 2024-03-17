package com.gskart.user.DTOs;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UserDto {
    private String username;
    private Set<RoleDto> roles;
}
