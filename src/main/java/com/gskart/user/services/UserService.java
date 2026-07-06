package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.requests.UpdateUserRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserNotFoundException;
import com.gskart.user.repositories.RoleRepository;
import com.gskart.user.repositories.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService implements IUserService {

    private static final String DEFAULT_ROLE_NAME = "USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository,
                        BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    @Transactional
    public User register(SignUpRequest signUpRequest) throws UserAlreadyRegisteredException {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserAlreadyRegisteredException(
                    String.format("User with email %s already registered.", signUpRequest.getEmail()));
        }
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new UserAlreadyRegisteredException(
                    String.format("User with username %s already registered.", signUpRequest.getUsername()));
        }

        // Self-registration never honors client-supplied roles (privilege-escalation guard, D14);
        // every new user gets the default role and roles are managed via RoleController afterward.
        Role defaultRole = findOrCreateDefaultRole();

        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setFirstname(signUpRequest.getFirstname());
        user.setLastname(signUpRequest.getLastname());
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(signUpRequest.getPassword()));
        user.setRoles(Set.of(defaultRole));
        user.setUserStatus(User.UserStatus.ACTIVE);
        user.setCredentialsStatus(User.CredentialsStatus.ACTIVE);
        user.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        user.setCreatedBy(signUpRequest.getUsername());

        return userRepository.save(user);
    }

    @Override
    public User getUser(Long id) throws UserNotFoundException {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(String.format("User with id %d does not exist", id)));
    }

    @Override
    public Page<User> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    @Override
    @Transactional
    public User updateUser(Long id, UpdateUserRequest updateUserRequest, String modifiedBy)
            throws UserNotFoundException, UserAlreadyRegisteredException {
        User user = getUser(id);

        Optional<User> emailOwner = userRepository.findByEmail(updateUserRequest.getEmail());
        if (emailOwner.isPresent() && !emailOwner.get().getId().equals(id)) {
            throw new UserAlreadyRegisteredException(
                    String.format("User with email %s already registered.", updateUserRequest.getEmail()));
        }

        user.setFirstname(updateUserRequest.getFirstname());
        user.setLastname(updateUserRequest.getLastname());
        user.setEmail(updateUserRequest.getEmail());
        user.setModifiedBy(modifiedBy);
        user.setModifiedOn(OffsetDateTime.now(ZoneOffset.UTC));
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public void inactivateUser(Long id, String modifiedBy) throws UserNotFoundException {
        User user = getUser(id);
        user.setUserStatus(User.UserStatus.DELETED);
        user.setModifiedBy(modifiedBy);
        user.setModifiedOn(OffsetDateTime.now(ZoneOffset.UTC));
        userRepository.save(user);
    }

    private Role findOrCreateDefaultRole() {
        Optional<Role> existing = roleRepository.findByName(DEFAULT_ROLE_NAME);
        if (existing.isPresent()) {
            return existing.get();
        }
        try {
            Role role = new Role();
            role.setName(DEFAULT_ROLE_NAME);
            role.setDescription("Default role granted on self-registration");
            role.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
            role.setCreatedBy("system");
            return roleRepository.save(role);
        } catch (DataIntegrityViolationException e) {
            // Lost a race with a concurrent first registration that created the default role
            // first; fetch what it created instead of failing this signup.
            return roleRepository.findByName(DEFAULT_ROLE_NAME).orElseThrow(() -> e);
        }
    }
}
