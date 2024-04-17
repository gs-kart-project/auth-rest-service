package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.*;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.repositories.UserRepository;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AuthService implements IAuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtHelper jwtHelper;
    private final Mapper mapper;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, JwtHelper jwtHelper, Mapper mapper) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtHelper = jwtHelper;
        this.mapper = mapper;
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
        user.setCreatedBy(signUpRequest.getUsername());
        user.setUserStatus(User.UserStatus.ACTIVE);
        user.setCredentialsStatus(User.CredentialsStatus.ACTIVE);
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

    public LoginResult login(String username, String password) throws UserNotExistsException, JwtKeyStoreException {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isEmpty()){
            throw new UserNotExistsException(String.format("User with username %s does not exist", username));
        }

        User user = optionalUser.get();
        if(!bCryptPasswordEncoder.matches(password, user.getPassword())){
            // Invalid credentials provided.
            return null;
        }

        // Need to handle User expiry, Credentials expiry etc.

        // Generate token and add to Header
        String accessToken = jwtHelper.generateToken(user.getUsername(), user.getEmail(), mapper.rolesEntitySetToRolesDtoSet(user.getRoles()));
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.SET_COOKIE, accessToken);

        LoginResult loginResult = new LoginResult();
        loginResult.setUser(user);
        loginResult.setAuthenticationHeader(headers);
        return loginResult;
    }

    @Override
    public boolean validateToken(String token, String username) throws JwtKeyStoreException {
        return jwtHelper.validateToken(token, username);
    }

    @Override
    public Claims getClaimsFromToken(String token) throws JwtNotValidException, JwtKeyStoreException {
        return jwtHelper.getClaimsFromToken(token);
    }
}