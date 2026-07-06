package com.gskart.user.controllers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IRoleService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleControllerTest {

    @Mock
    private IRoleService roleService;
    @Mock
    private Mapper mapper;

    private RoleController roleController;

    @BeforeEach
    void setUp() {
        roleController = new RoleController(roleService, mapper);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin", null, List.of()));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private RoleRequest buildRoleRequest() {
        RoleRequest request = new RoleRequest();
        request.setName("ADMIN");
        request.setDescription("Administrator");
        return request;
    }

    @Test
    void createRole_returns201WithLocation_whenSucceeds() throws Exception {
        RoleRequest request = buildRoleRequest();
        Role role = new Role();
        role.setId(7L);
        RoleDto dto = new RoleDto();
        when(roleService.createRole(eq(request), eq("admin"))).thenReturn(role);
        when(mapper.roleEntityToDto(role)).thenReturn(dto);

        ResponseEntity<RoleDto> response = roleController.createRole(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getHeaders().getLocation().toString()).isEqualTo("/api/v1/roles/7");
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void createRole_propagatesRoleAlreadyExistsException_whenDuplicate() throws Exception {
        RoleRequest request = buildRoleRequest();
        when(roleService.createRole(eq(request), eq("admin")))
                .thenThrow(new RoleAlreadyExistsException("dup"));

        assertThatThrownBy(() -> roleController.createRole(request))
                .isInstanceOf(RoleAlreadyExistsException.class);
    }

    @Test
    void getRoleById_returnsRole_whenFound() throws Exception {
        Role role = new Role();
        RoleDto dto = new RoleDto();
        when(roleService.getRole(1L)).thenReturn(role);
        when(mapper.roleEntityToDto(role)).thenReturn(dto);

        ResponseEntity<RoleDto> response = roleController.getRoleById(1L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void getRoleById_propagatesRoleNotFoundException_whenMissing() throws Exception {
        when(roleService.getRole(99L)).thenThrow(new RoleNotFoundException("missing"));

        assertThatThrownBy(() -> roleController.getRoleById(99L)).isInstanceOf(RoleNotFoundException.class);
    }

    @Test
    void listRoles_returnsMappedList() {
        Role role = new Role();
        RoleDto dto = new RoleDto();
        when(roleService.listRoles()).thenReturn(List.of(role));
        when(mapper.roleEntityToDto(role)).thenReturn(dto);

        ResponseEntity<List<RoleDto>> response = roleController.listRoles();

        assertThat(response.getBody()).containsExactly(dto);
    }

    @Test
    void updateRole_returnsUpdatedRole_whenSucceeds() throws Exception {
        RoleRequest request = buildRoleRequest();
        Role role = new Role();
        RoleDto dto = new RoleDto();
        when(roleService.updateRole(eq(1L), eq(request), eq("admin"))).thenReturn(role);
        when(mapper.roleEntityToDto(role)).thenReturn(dto);

        ResponseEntity<RoleDto> response = roleController.updateRole(1L, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void updateRole_propagatesRoleNotFoundException_whenMissing() throws Exception {
        RoleRequest request = buildRoleRequest();
        when(roleService.updateRole(eq(99L), eq(request), eq("admin")))
                .thenThrow(new RoleNotFoundException("missing"));

        assertThatThrownBy(() -> roleController.updateRole(99L, request))
                .isInstanceOf(RoleNotFoundException.class);
    }

    @Test
    void deleteRole_returns204_whenSucceeds() throws Exception {
        ResponseEntity<Void> response = roleController.deleteRole(1L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void deleteRole_propagatesRoleNotFoundException_whenMissing() throws Exception {
        org.mockito.Mockito.doThrow(new RoleNotFoundException("missing")).when(roleService).deleteRole(99L);

        assertThatThrownBy(() -> roleController.deleteRole(99L)).isInstanceOf(RoleNotFoundException.class);
    }
}
