package com.gskart.user.security.models;

import com.gskart.user.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class GSKartUserDetails implements UserDetails {

    private final User user;

    public GSKartUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(!user.getRoles().isEmpty()){
            Collection<GSKartRole> gsKartRoleList;
            gsKartRoleList = user.getRoles().stream().map(GSKartRole::new).toList();
            return gsKartRoleList;
        }
        else{
            return new ArrayList<>();
        }
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        // Todo Need to implement user expiry
        return user.getUserStatus() == User.UserStatus.ACTIVE;
    }

    @Override
    public boolean isAccountNonLocked() {
        // Todo Need to implement account locking strategy
        return user.getUserStatus() == User.UserStatus.ACTIVE;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // Todo To be same as user expiry
        return user.getCredentialsStatus() == User.CredentialsStatus.ACTIVE;
    }

    @Override
    public boolean isEnabled() {
        return user.getUserStatus() == User.UserStatus.ACTIVE;
    }

    public User getUserEntity(){ return user; }
}
