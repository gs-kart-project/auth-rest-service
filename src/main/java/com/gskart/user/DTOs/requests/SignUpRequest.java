package com.gskart.user.DTOs.requests;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.entities.Role;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class SignUpRequest {
    private String firstname;
    private String lastname;
    private String email;
    private String username;
    private String password;
    private Set<RoleDto> roles;
}
