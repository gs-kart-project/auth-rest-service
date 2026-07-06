package com.gskart.user.services;

import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;

import java.util.List;

public interface IRoleService {
    Role createRole(RoleRequest roleRequest, String createdBy) throws RoleAlreadyExistsException;

    Role getRole(Long id) throws RoleNotFoundException;

    List<Role> listRoles();

    Role updateRole(Long id, RoleRequest roleRequest, String modifiedBy) throws RoleNotFoundException;

    void deleteRole(Long id) throws RoleNotFoundException;
}
