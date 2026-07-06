package com.gskart.user.services;

import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.repositories.RoleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Service
public class RoleService implements IRoleService {

    private final RoleRepository roleRepository;
    private final Mapper mapper;

    public RoleService(RoleRepository roleRepository, Mapper mapper) {
        this.roleRepository = roleRepository;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public Role createRole(RoleRequest roleRequest, String createdBy) throws RoleAlreadyExistsException {
        if (roleRepository.existsByName(roleRequest.getName())) {
            throw new RoleAlreadyExistsException(
                    String.format("Role with name %s already exists.", roleRequest.getName()));
        }
        Role role = mapper.roleRequestToEntity(roleRequest);
        role.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        role.setCreatedBy(createdBy);
        return roleRepository.save(role);
    }

    @Override
    public Role getRole(Long id) throws RoleNotFoundException {
        return roleRepository.findById(id)
                .orElseThrow(() -> new RoleNotFoundException(String.format("Role with id %d does not exist", id)));
    }

    @Override
    public List<Role> listRoles() {
        return roleRepository.findAll();
    }

    @Override
    @Transactional
    public Role updateRole(Long id, RoleRequest roleRequest, String modifiedBy) throws RoleNotFoundException {
        Role role = getRole(id);
        role.setName(roleRequest.getName());
        role.setDescription(roleRequest.getDescription());
        role.setModifiedBy(modifiedBy);
        role.setModifiedOn(OffsetDateTime.now(ZoneOffset.UTC));
        return roleRepository.save(role);
    }

    @Override
    @Transactional
    public void deleteRole(Long id) throws RoleNotFoundException {
        Role role = getRole(id);
        roleRepository.delete(role);
    }
}
