package com.gskart.user.entities;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import lombok.Builder;
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
    @ManyToMany(cascade = CascadeType.ALL)
    private Set<Role> roles;
}
