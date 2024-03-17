package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AuthService implements IAuthService {

    final UserRepository userRepository;
    final BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public User signup(SignUpRequest signUpRequest) throws UserException, UserAlreadyRegisteredException {
        if(userRepository.existsByEmail(signUpRequest.getEmail())){
            throw new UserAlreadyRegisteredException(String.format("User with email %s already registered.", signUpRequest.getEmail()));
        }

        if(userRepository.existsByUsername(signUpRequest.getUsername())){
            throw new UserAlreadyRegisteredException(String.format("User with username %s already registered.", signUpRequest.getUsername()));
        }

        // validate for user role. User is expected to have at least one Role
        if(signUpRequest.getRoles() == null || signUpRequest.getRoles().isEmpty()){
            throw new UserException("No roles associated with the user. User must contain at least one role.");
        }

        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setLastname(signUpRequest.getLastname());
        user.setFirstname(signUpRequest.getFirstname());
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(signUpRequest.getPassword()));
        user.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        //user.setModifiedOn(OffsetDateTime.now(ZoneOffset.UTC));
        // TODO created by and modified by should be set based on the User who sent the request

        if(signUpRequest.getRoles()!=null) {
            user.setRoles(signUpRequest.getRoles().stream().map(roleDto -> {
                Role role = new Role();
                role.setName(roleDto.getName());
                role.setDescription(roleDto.getDescription());
                return role;
            }).collect(Collectors.toSet()));
        }
        User savedUser = userRepository.save(user);
        return savedUser;
    }

    public User login(String username, String password) throws UserNotExistsException {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isEmpty()){
            throw new UserNotExistsException(String.format("User with username %s does not exist", username));
        }

        User user = optionalUser.get();
        if(!bCryptPasswordEncoder.matches(password, user.getPassword())){
            // Invalid credentials provided.
            return null;
        }
        return user;
    }
}
