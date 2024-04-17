package com.gskart.user.security.models;

import com.gskart.user.entities.Role;
import org.springframework.security.core.GrantedAuthority;

public class GSKartRole implements GrantedAuthority {

    private final Role role;

    public GSKartRole(Role role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role.getName();
    }
}
