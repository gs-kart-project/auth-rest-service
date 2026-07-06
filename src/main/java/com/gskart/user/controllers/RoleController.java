package com.gskart.user.controllers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.requests.RoleRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IRoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@PreAuthorize("hasAuthority('Developer')")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Roles", description = "Role management")
public class RoleController {

    private final IRoleService roleService;
    private final Mapper mapper;

    public RoleController(IRoleService roleService, Mapper mapper) {
        this.roleService = roleService;
        this.mapper = mapper;
    }

    @Operation(summary = "Create a role")
    @PostMapping
    public ResponseEntity<RoleDto> createRole(@Valid @RequestBody RoleRequest roleRequest)
            throws RoleAlreadyExistsException {
        Role role = roleService.createRole(roleRequest, currentUsername());
        return ResponseEntity.created(URI.create("/api/v1/roles/" + role.getId()))
                .body(mapper.roleEntityToDto(role));
    }

    @Operation(summary = "Get a role by id")
    @GetMapping("/{id}")
    public ResponseEntity<RoleDto> getRoleById(@PathVariable Long id) throws RoleNotFoundException {
        return ResponseEntity.ok(mapper.roleEntityToDto(roleService.getRole(id)));
    }

    @Operation(summary = "List all roles")
    @GetMapping
    public ResponseEntity<List<RoleDto>> listRoles() {
        return ResponseEntity.ok(roleService.listRoles().stream().map(mapper::roleEntityToDto).toList());
    }

    @Operation(summary = "Update a role")
    @PutMapping("/{id}")
    public ResponseEntity<RoleDto> updateRole(@PathVariable Long id, @Valid @RequestBody RoleRequest roleRequest)
            throws RoleNotFoundException {
        Role role = roleService.updateRole(id, roleRequest, currentUsername());
        return ResponseEntity.ok(mapper.roleEntityToDto(role));
    }

    @Operation(summary = "Delete a role")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) throws RoleNotFoundException {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }

    private String currentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
