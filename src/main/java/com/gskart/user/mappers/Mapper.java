package com.gskart.user.mappers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.DTOs.response.UserDetailsDto;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class Mapper {

    public Set<RoleDto> rolesEntitySetToRolesDtoSet(Set<Role> roles) {
        return roles.stream().map(this::roleEntityToDto).collect(Collectors.toSet());
    }

    public Set<Role> rolesDtoSetToRolesEntitySet(Set<RoleDto> roleDtoSet) {
        return roleDtoSet.stream().map(roleDto -> {
            Role role = new Role();
            role.setName(roleDto.getName());
            role.setDescription(roleDto.getDescription());
            return role;
        }).collect(Collectors.toSet());
    }


    public UserDetailsDto userEntityToDetailsDto(User user) {
        UserDetailsDto dto = new UserDetailsDto();
        dto.setId(user.getId());
        dto.setFirstname(user.getFirstname());
        dto.setLastname(user.getLastname());
        dto.setEmail(user.getEmail());
        dto.setUsername(user.getUsername());
        dto.setRoles(rolesEntitySetToRolesDtoSet(user.getRoles()));
        dto.setUserStatus(user.getUserStatus().name());
        return dto;
    }

    public RoleDto roleEntityToDto(Role role) {
        RoleDto roleDto = new RoleDto();
        roleDto.setName(role.getName());
        roleDto.setDescription(role.getDescription());
        return roleDto;
    }

    public Role roleRequestToEntity(RoleRequest roleRequest) {
        Role role = new Role();
        role.setName(roleRequest.getName());
        role.setDescription(roleRequest.getDescription());
        return role;
    }
}
