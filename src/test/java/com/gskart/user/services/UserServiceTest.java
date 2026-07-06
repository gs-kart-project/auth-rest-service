package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.requests.UpdateUserRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserNotFoundException;
import com.gskart.user.repositories.RoleRepository;
import com.gskart.user.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, roleRepository, bCryptPasswordEncoder);
    }

    private SignUpRequest buildSignUpRequest() {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setFirstname("Jane");
        signUpRequest.setLastname("Doe");
        signUpRequest.setEmail("jdoe@example.com");
        signUpRequest.setUsername("jdoe");
        signUpRequest.setPassword("password");
        return signUpRequest;
    }

    private Role buildDefaultRole() {
        Role role = new Role();
        role.setId(1L);
        role.setName("USER");
        return role;
    }

    @Test
    void register_savesUserWithEncodedPasswordAndDefaultRole_whenRequestIsValid() throws Exception {
        SignUpRequest signUpRequest = buildSignUpRequest();
        Role defaultRole = buildDefaultRole();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(defaultRole));
        when(bCryptPasswordEncoder.encode("password")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User savedUser = userService.register(signUpRequest);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();

        assertThat(capturedUser.getPassword()).isEqualTo("hashed-password");
        assertThat(capturedUser.getUserStatus()).isEqualTo(User.UserStatus.ACTIVE);
        assertThat(capturedUser.getCredentialsStatus()).isEqualTo(User.CredentialsStatus.ACTIVE);
        assertThat(capturedUser.getRoles()).containsExactly(defaultRole);
        assertThat(capturedUser.getCreatedOn()).isNotNull();
        assertThat(capturedUser.getCreatedBy()).isEqualTo("jdoe");
        assertThat(savedUser).isSameAs(capturedUser);
    }

    @Test
    void register_createsDefaultRole_whenItDoesNotYetExist() throws Exception {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.empty());
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(bCryptPasswordEncoder.encode("password")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        userService.register(signUpRequest);

        ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(roleCaptor.capture());
        assertThat(roleCaptor.getValue().getName()).isEqualTo("USER");
    }

    @Test
    void register_refetchesDefaultRole_whenConcurrentCreationLosesUniqueConstraintRace() throws Exception {
        SignUpRequest signUpRequest = buildSignUpRequest();
        Role concurrentlyCreatedRole = buildDefaultRole();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);
        when(roleRepository.findByName("USER"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(concurrentlyCreatedRole));
        when(roleRepository.save(any(Role.class))).thenThrow(new DataIntegrityViolationException("duplicate"));
        when(bCryptPasswordEncoder.encode("password")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User savedUser = userService.register(signUpRequest);

        assertThat(savedUser.getRoles()).containsExactly(concurrentlyCreatedRole);
    }

    @Test
    void register_throwsUserAlreadyRegisteredException_whenEmailAlreadyRegistered() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.register(signUpRequest))
                .isInstanceOf(UserAlreadyRegisteredException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_throwsUserAlreadyRegisteredException_whenUsernameAlreadyRegistered() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(true);

        assertThatThrownBy(() -> userService.register(signUpRequest))
                .isInstanceOf(UserAlreadyRegisteredException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void getUser_returnsUser_whenIdExists() throws Exception {
        User user = new User();
        user.setId(1L);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        assertThat(userService.getUser(1L)).isSameAs(user);
    }

    @Test
    void getUser_throwsUserNotFoundException_whenIdDoesNotExist() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUser(99L))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void listUsers_returnsPageFromRepository() {
        Page<User> page = new PageImpl<>(List.of(new User()));
        Pageable pageable = Pageable.ofSize(20);
        when(userRepository.findAll(pageable)).thenReturn(page);

        assertThat(userService.listUsers(pageable)).isSameAs(page);
    }

    @Test
    void updateUser_updatesProfileFieldsAndModifiedBy_whenUserExists() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setFirstname("Old");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UpdateUserRequest request = new UpdateUserRequest();
        request.setFirstname("New");
        request.setLastname("Name");
        request.setEmail("new@example.com");

        User updated = userService.updateUser(1L, request, "admin");

        assertThat(updated.getFirstname()).isEqualTo("New");
        assertThat(updated.getLastname()).isEqualTo("Name");
        assertThat(updated.getEmail()).isEqualTo("new@example.com");
        assertThat(updated.getModifiedBy()).isEqualTo("admin");
        assertThat(updated.getModifiedOn()).isNotNull();
    }

    @Test
    void updateUser_allowsUnchangedEmail_whenEmailBelongsToSameUser() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setEmail("same@example.com");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.findByEmail("same@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UpdateUserRequest request = new UpdateUserRequest();
        request.setFirstname("New");
        request.setLastname("Name");
        request.setEmail("same@example.com");

        User updated = userService.updateUser(1L, request, "admin");

        assertThat(updated.getEmail()).isEqualTo("same@example.com");
    }

    @Test
    void updateUser_throwsUserAlreadyRegisteredException_whenEmailBelongsToAnotherUser() {
        User user = new User();
        user.setId(1L);
        User otherUser = new User();
        otherUser.setId(2L);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.findByEmail("taken@example.com")).thenReturn(Optional.of(otherUser));

        UpdateUserRequest request = new UpdateUserRequest();
        request.setFirstname("New");
        request.setLastname("Name");
        request.setEmail("taken@example.com");

        assertThatThrownBy(() -> userService.updateUser(1L, request, "admin"))
                .isInstanceOf(UserAlreadyRegisteredException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateUser_throwsUserNotFoundException_whenUserDoesNotExist() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        UpdateUserRequest request = new UpdateUserRequest();
        assertThatThrownBy(() -> userService.updateUser(99L, request, "admin"))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void inactivateUser_setsUserStatusDeleted_whenUserExists() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUserStatus(User.UserStatus.ACTIVE);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        userService.inactivateUser(1L, "admin");

        assertThat(user.getUserStatus()).isEqualTo(User.UserStatus.DELETED);
        assertThat(user.getModifiedBy()).isEqualTo("admin");
    }
}
