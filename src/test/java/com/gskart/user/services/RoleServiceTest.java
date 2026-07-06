package com.gskart.user.services;

import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.repositories.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;
    @Mock
    private Mapper mapper;

    private RoleService roleService;

    @BeforeEach
    void setUp() {
        roleService = new RoleService(roleRepository, mapper);
    }

    private RoleRequest buildRoleRequest() {
        RoleRequest request = new RoleRequest();
        request.setName("ADMIN");
        request.setDescription("Administrator");
        return request;
    }

    @Test
    void createRole_savesRole_whenNameNotTaken() throws Exception {
        RoleRequest roleRequest = buildRoleRequest();
        Role mappedRole = new Role();
        mappedRole.setName("ADMIN");
        mappedRole.setDescription("Administrator");
        when(roleRepository.existsByName("ADMIN")).thenReturn(false);
        when(mapper.roleRequestToEntity(roleRequest)).thenReturn(mappedRole);
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Role role = roleService.createRole(roleRequest, "admin");

        assertThat(role.getName()).isEqualTo("ADMIN");
        assertThat(role.getCreatedBy()).isEqualTo("admin");
    }

    @Test
    void createRole_throwsRoleAlreadyExistsException_whenNameTaken() {
        RoleRequest roleRequest = buildRoleRequest();
        when(roleRepository.existsByName("ADMIN")).thenReturn(true);

        assertThatThrownBy(() -> roleService.createRole(roleRequest, "admin"))
                .isInstanceOf(RoleAlreadyExistsException.class);
        verify(roleRepository, never()).save(any());
    }

    @Test
    void getRole_returnsRole_whenIdExists() throws Exception {
        Role role = new Role();
        role.setId(1L);
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));

        assertThat(roleService.getRole(1L)).isSameAs(role);
    }

    @Test
    void getRole_throwsRoleNotFoundException_whenIdDoesNotExist() {
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.getRole(99L))
                .isInstanceOf(RoleNotFoundException.class);
    }

    @Test
    void listRoles_returnsAllRoles() {
        Role role = new Role();
        when(roleRepository.findAll()).thenReturn(java.util.List.of(role));

        assertThat(roleService.listRoles()).containsExactly(role);
    }

    @Test
    void updateRole_updatesNameAndDescriptionAndModifiedBy_whenRoleExists() throws Exception {
        Role role = new Role();
        role.setId(1L);
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RoleRequest roleRequest = new RoleRequest();
        roleRequest.setName("ADMIN");
        roleRequest.setDescription("Updated");

        Role updated = roleService.updateRole(1L, roleRequest, "admin");

        assertThat(updated.getName()).isEqualTo("ADMIN");
        assertThat(updated.getDescription()).isEqualTo("Updated");
        assertThat(updated.getModifiedBy()).isEqualTo("admin");
    }

    @Test
    void updateRole_throwsRoleNotFoundException_whenRoleDoesNotExist() {
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        RoleRequest roleRequest = buildRoleRequest();
        assertThatThrownBy(() -> roleService.updateRole(99L, roleRequest, "admin"))
                .isInstanceOf(RoleNotFoundException.class);
    }

    @Test
    void deleteRole_deletesRole_whenRoleExists() throws Exception {
        Role role = new Role();
        role.setId(1L);
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));

        roleService.deleteRole(1L);

        verify(roleRepository).delete(role);
    }

    @Test
    void deleteRole_throwsRoleNotFoundException_whenRoleDoesNotExist() {
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.deleteRole(99L))
                .isInstanceOf(RoleNotFoundException.class);
    }
}
