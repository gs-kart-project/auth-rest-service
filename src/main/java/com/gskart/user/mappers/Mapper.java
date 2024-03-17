package com.gskart.user.mappers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.UserDto;
import com.gskart.user.entities.User;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class Mapper {
    public UserDto userEntityToDto(User user){
        UserDto userDto = new UserDto();
        userDto.setUsername(user.getUsername());
        if(user.getRoles() != null){
            userDto.setRoles(user.getRoles().stream().map(role ->{
                RoleDto roleDto = new RoleDto();
                roleDto.setName(role.getName());
                return roleDto;
            }).collect(Collectors.toSet()));
        }
        return userDto;
    }
}
