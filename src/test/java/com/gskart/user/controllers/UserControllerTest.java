package com.gskart.user.controllers;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.requests.UpdateUserRequest;
import com.gskart.user.DTOs.response.UserDetailsDto;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserNotFoundException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IUserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private IUserService userService;
    @Mock
    private Mapper mapper;

    private UserController userController;

    @BeforeEach
    void setUp() {
        userController = new UserController(userService, mapper);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String username) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(username, null, List.of()));
    }

    private SignUpRequest buildSignUpRequest() {
        SignUpRequest request = new SignUpRequest();
        request.setFirstname("Jane");
        request.setLastname("Doe");
        request.setEmail("jdoe@example.com");
        request.setUsername("jdoe");
        request.setPassword("password");
        return request;
    }

    @Test
    void signUp_returns201WithLocation_whenRegistrationSucceeds() throws Exception {
        User user = new User();
        user.setId(42L);
        UserDetailsDto dto = new UserDetailsDto();
        when(userService.register(any(SignUpRequest.class))).thenReturn(user);
        when(mapper.userEntityToDetailsDto(user)).thenReturn(dto);

        ResponseEntity<UserDetailsDto> response = userController.signUp(buildSignUpRequest());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getHeaders().getLocation().toString()).isEqualTo("/api/v1/users/42");
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void signUp_propagatesUserAlreadyRegisteredException_whenDuplicate() throws Exception {
        SignUpRequest request = buildSignUpRequest();
        when(userService.register(any(SignUpRequest.class)))
                .thenThrow(new UserAlreadyRegisteredException("dup"));

        assertThatThrownBy(() -> userController.signUp(request))
                .isInstanceOf(UserAlreadyRegisteredException.class);
    }

    @Test
    void getUserById_returnsUser_whenFound() throws Exception {
        User user = new User();
        UserDetailsDto dto = new UserDetailsDto();
        when(userService.getUser(1L)).thenReturn(user);
        when(mapper.userEntityToDetailsDto(user)).thenReturn(dto);

        ResponseEntity<UserDetailsDto> response = userController.getUserById(1L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void getUserById_propagatesUserNotFoundException_whenMissing() throws Exception {
        when(userService.getUser(99L)).thenThrow(new UserNotFoundException("missing"));

        assertThatThrownBy(() -> userController.getUserById(99L)).isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void listUsers_returnsMappedPage() {
        Page<User> userPage = new PageImpl<>(List.of(new User()));
        UserDetailsDto dto = new UserDetailsDto();
        when(userService.listUsers(any(Pageable.class))).thenReturn(userPage);
        when(mapper.userEntityToDetailsDto(any(User.class))).thenReturn(dto);

        ResponseEntity<Page<UserDetailsDto>> response = userController.listUsers(Pageable.ofSize(20));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getContent()).containsExactly(dto);
    }

    @Test
    void updateUser_returnsUpdatedUser_whenSucceeds() throws Exception {
        authenticateAs("admin");
        User user = new User();
        UserDetailsDto dto = new UserDetailsDto();
        UpdateUserRequest request = new UpdateUserRequest();
        when(userService.updateUser(eq(1L), eq(request), eq("admin"))).thenReturn(user);
        when(mapper.userEntityToDetailsDto(user)).thenReturn(dto);

        ResponseEntity<UserDetailsDto> response = userController.updateUser(1L, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(dto);
    }

    @Test
    void updateUser_propagatesUserNotFoundException_whenMissing() throws Exception {
        authenticateAs("admin");
        UpdateUserRequest request = new UpdateUserRequest();
        when(userService.updateUser(eq(99L), eq(request), eq("admin")))
                .thenThrow(new UserNotFoundException("missing"));

        assertThatThrownBy(() -> userController.updateUser(99L, request))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void updateUser_propagatesUserAlreadyRegisteredException_whenEmailBelongsToAnotherUser() throws Exception {
        authenticateAs("admin");
        UpdateUserRequest request = new UpdateUserRequest();
        when(userService.updateUser(eq(1L), eq(request), eq("admin")))
                .thenThrow(new UserAlreadyRegisteredException("taken"));

        assertThatThrownBy(() -> userController.updateUser(1L, request))
                .isInstanceOf(UserAlreadyRegisteredException.class);
    }

    @Test
    void deleteUser_returns204_whenSucceeds() throws Exception {
        authenticateAs("admin");

        ResponseEntity<Void> response = userController.deleteUser(1L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void deleteUser_propagatesUserNotFoundException_whenMissing() throws Exception {
        authenticateAs("admin");
        org.mockito.Mockito.doThrow(new UserNotFoundException("missing"))
                .when(userService).inactivateUser(99L, "admin");

        assertThatThrownBy(() -> userController.deleteUser(99L)).isInstanceOf(UserNotFoundException.class);
    }
}
