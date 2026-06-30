package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.BlacklistedToken;
import com.gskart.user.entities.RefreshToken;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.*;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.repositories.RefreshTokenRepository;
import com.gskart.user.repositories.UserRepository;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuthService implements IAuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtHelper jwtHelper;
    private final Mapper mapper;

    @Value("${gskart.jwt.refresh-token.expiry-days}")
    private long refreshTokenExpiryDays;

    public AuthService(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository,
                        BlacklistedTokenRepository blacklistedTokenRepository, BCryptPasswordEncoder bCryptPasswordEncoder,
                        JwtHelper jwtHelper, Mapper mapper) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.blacklistedTokenRepository = blacklistedTokenRepository;
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

        return buildLoginResult(user);
    }

    @Override
    public Claims getClaimsFromToken(String token) throws JwtNotValidException, JwtKeyStoreException {
        return jwtHelper.getClaimsFromToken(token);
    }

    @Override
    @Transactional
    public LoginResult refresh(String refreshToken) throws RefreshTokenException, JwtKeyStoreException {
        RefreshToken existingToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RefreshTokenException("Refresh token not recognized."));

        if(existingToken.getExpiresOn().isBefore(OffsetDateTime.now(ZoneOffset.UTC))){
            throw new RefreshTokenException("Refresh token is expired or has been revoked.");
        }

        // Conditional update so concurrent requests for the same token can't both pass the
        // revoked check and rotate it; only the first writer gets 1 row updated.
        if(refreshTokenRepository.revokeIfActive(refreshToken) == 0){
            throw new RefreshTokenException("Refresh token is expired or has been revoked.");
        }

        User user = userRepository.findByUsername(existingToken.getUsername())
                .orElseThrow(() -> new RefreshTokenException(String.format("User with username %s does not exist", existingToken.getUsername())));

        return buildLoginResult(user);
    }

    @Override
    @Transactional
    public void logout(String accessToken) throws JwtKeyStoreException, JwtNotValidException {
        Claims claims = jwtHelper.getClaimsFromToken(accessToken);

        BlacklistedToken blacklistedToken = new BlacklistedToken();
        blacklistedToken.setTokenId(claims.getId());
        blacklistedToken.setExpiresOn(OffsetDateTime.ofInstant(claims.getExpiration().toInstant(), ZoneOffset.UTC));
        blacklistedTokenRepository.save(blacklistedToken);

        List<RefreshToken> activeRefreshTokens = refreshTokenRepository.findByUsernameAndRevokedFalse(claims.getSubject());
        activeRefreshTokens.forEach(refreshToken -> refreshToken.setRevoked(true));
        refreshTokenRepository.saveAll(activeRefreshTokens);
    }

    private LoginResult buildLoginResult(User user) throws JwtKeyStoreException {
        String accessToken = jwtHelper.generateToken(user.getUsername(), user.getEmail(), mapper.rolesEntitySetToRolesDtoSet(user.getRoles()));
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        LoginResult loginResult = new LoginResult();
        loginResult.setUser(user);
        loginResult.setAuthenticationHeader(headers);
        loginResult.setRefreshToken(createRefreshToken(user.getUsername()));
        return loginResult;
    }

    private String createRefreshToken(String username) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUsername(username);
        refreshToken.setRevoked(false);
        refreshToken.setCreatedOn(OffsetDateTime.now(ZoneOffset.UTC));
        refreshToken.setCreatedBy(username);
        refreshToken.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).plus(refreshTokenExpiryDays, ChronoUnit.DAYS));
        refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }
}
