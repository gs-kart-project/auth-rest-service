package com.gskart.user.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@Entity(name = "users")
public class User extends BaseEntity{
    private String firstname;
    private String lastname;
    private String email;
    private String username;
    private String password;
    //As user can have multiple roles
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private Set<Role> roles;

    @Enumerated(EnumType.ORDINAL)
    private UserStatus userStatus;

    @Enumerated(EnumType.ORDINAL)
    private CredentialsStatus credentialsStatus;

    @Getter
    public enum UserStatus{
        IN_ACTIVE,
        ACTIVE,
        DELETED,
        LOCKED
    }

    public enum CredentialsStatus{
        EXPIRED,
        ACTIVE
    }
}
