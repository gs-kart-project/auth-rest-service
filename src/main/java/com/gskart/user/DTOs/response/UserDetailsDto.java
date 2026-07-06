package com.gskart.user.DTOs.response;

import com.gskart.user.DTOs.RoleDto;
import lombok.Data;

import java.util.Set;

@Data
public class UserDetailsDto {
    private Long id;
    private String firstname;
    private String lastname;
    private String email;
    private String username;
    private Set<RoleDto> roles;
    private String userStatus;
}
