package com.gskart.user.mappers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.response.ClaimsResponse;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class Mapper {
    public UserDto userEntityToDto(User user){
        UserDto userDto = new UserDto();
        userDto.setUsername(user.getUsername());
        if(user.getRoles() != null){
            userDto.setRoles(rolesEntitySetToRolesDtoSet(user.getRoles()));
        }
        return userDto;
    }

    public Set<RoleDto> rolesEntitySetToRolesDtoSet(Set<Role> roles) {
        return roles.stream().map(role -> {
            RoleDto roleDto = new RoleDto();
            roleDto.setName(role.getName());
            return roleDto;
        }).collect(Collectors.toSet());
    }

    public Set<Role> rolesDtoSetToRolesEntitySet(Set<RoleDto> roleDtoSet) {
        return roleDtoSet.stream().map(roleDto -> {
            Role role = new Role();
            role.setName(roleDto.getName());
            return role;
        }).collect(Collectors.toSet());
    }

    public ClaimsResponse claimsToClaimsResponse(Claims claims) {
        ClaimsResponse claimsResponse = new ClaimsResponse();
        claimsResponse.setUsername(claims.getSubject());
        claimsResponse.setEmail(claims.get("email", String.class));
        Set<RoleDto> roleDtoSet = (Set<RoleDto>) claims.get("roles");
        claimsResponse.setRoles(roleDtoSet);
        return claimsResponse;
    }

    public ClaimsResponse userEntityToClaimsResponse(User user) {
        ClaimsResponse claimsResponse = new ClaimsResponse();
        claimsResponse.setUsername(user.getUsername());
        claimsResponse.setEmail(user.getEmail());
        claimsResponse.setRoles(rolesEntitySetToRolesDtoSet(user.getRoles()));
        return claimsResponse;
    }
}
