package com.gskart.user.controllers;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.requests.UpdateUserRequest;
import com.gskart.user.DTOs.response.UserDetailsDto;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Users", description = "User registration and management")
public class UserController {

    private final IUserService userService;
    private final Mapper mapper;

    public UserController(IUserService userService, Mapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    /**
     * Sign up API - creates a new user resource (self-service, always granted the default role).
     */
    @Operation(summary = "Register a new user (self-service, always granted the default role)")
    @PostMapping("/users")
    public ResponseEntity<UserDetailsDto> signUp(@Valid @RequestBody SignUpRequest signUpRequest)
            throws UserAlreadyRegisteredException {
        User user = userService.register(signUpRequest);
        return ResponseEntity.created(URI.create("/api/v1/users/" + user.getId()))
                .body(mapper.userEntityToDetailsDto(user));
    }

    @Operation(summary = "Get a user by id")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/users/{id}")
    @PreAuthorize("hasAuthority('Developer')")
    public ResponseEntity<UserDetailsDto> getUserById(@PathVariable Long id) throws UserNotFoundException {
        User user = userService.getUser(id);
        return ResponseEntity.ok(mapper.userEntityToDetailsDto(user));
    }

    @Operation(summary = "List users (paginated)")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/users")
    @PreAuthorize("hasAuthority('Developer')")
    public ResponseEntity<Page<UserDetailsDto>> listUsers(Pageable pageable) {
        return ResponseEntity.ok(userService.listUsers(pageable).map(mapper::userEntityToDetailsDto));
    }

    @Operation(summary = "Update a user's profile fields")
    @SecurityRequirement(name = "bearerAuth")
    @PutMapping("/users/{id}")
    @PreAuthorize("hasAuthority('Developer')")
    public ResponseEntity<UserDetailsDto> updateUser(@PathVariable Long id,
                                                      @Valid @RequestBody UpdateUserRequest updateUserRequest)
            throws UserNotFoundException, UserAlreadyRegisteredException {
        User user = userService.updateUser(id, updateUserRequest, currentUsername());
        return ResponseEntity.ok(mapper.userEntityToDetailsDto(user));
    }

    @Operation(summary = "Inactivate a user (soft delete; sets userStatus=DELETED)")
    @SecurityRequirement(name = "bearerAuth")
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('Developer')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) throws UserNotFoundException {
        userService.inactivateUser(id, currentUsername());
        return ResponseEntity.noContent().build();
    }

    private String currentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
