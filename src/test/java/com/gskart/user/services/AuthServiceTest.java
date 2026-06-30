package com.gskart.user.services;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.BlacklistedToken;
import com.gskart.user.entities.RefreshToken;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.RefreshTokenException;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.repositories.RefreshTokenRepository;
import com.gskart.user.repositories.UserRepository;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;
    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Mock
    private JwtHelper jwtHelper;
    @Mock
    private Mapper mapper;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, refreshTokenRepository, blacklistedTokenRepository,
                bCryptPasswordEncoder, jwtHelper, mapper);
        ReflectionTestUtils.setField(authService, "refreshTokenExpiryDays", 7L);
    }

    private User buildUser() {
        User user = new User();
        user.setUsername("jdoe");
        user.setEmail("jdoe@example.com");
        user.setPassword("hashed-password");
        Role role = new Role();
        role.setName("USER");
        user.setRoles(Set.of(role));
        return user;
    }

    private SignUpRequest buildSignUpRequest() {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setFirstname("Jane");
        signUpRequest.setLastname("Doe");
        signUpRequest.setEmail("jdoe@example.com");
        signUpRequest.setUsername("jdoe");
        signUpRequest.setPassword("password");
        RoleDto roleDto = new RoleDto();
        roleDto.setName("USER");
        roleDto.setDescription("Standard user");
        signUpRequest.setRoles(Set.of(roleDto));
        return signUpRequest;
    }

    @Test
    void signup_savesUserWithEncodedPasswordAndActiveStatuses_whenRequestIsValid() throws Exception {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);
        when(bCryptPasswordEncoder.encode("password")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User savedUser = authService.signup(signUpRequest);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();

        assertThat(capturedUser.getPassword()).isEqualTo("hashed-password");
        assertThat(capturedUser.getUserStatus()).isEqualTo(User.UserStatus.ACTIVE);
        assertThat(capturedUser.getCredentialsStatus()).isEqualTo(User.CredentialsStatus.ACTIVE);
        assertThat(capturedUser.getCreatedOn()).isNotNull();
        assertThat(capturedUser.getCreatedBy()).isEqualTo("jdoe");
        assertThat(savedUser).isSameAs(capturedUser);
    }

    @Test
    void signup_throwsUserAlreadyRegisteredException_whenEmailAlreadyRegistered() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.signup(signUpRequest))
                .isInstanceOf(UserAlreadyRegisteredException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void signup_throwsUserAlreadyRegisteredException_whenUsernameAlreadyRegistered() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(true);

        assertThatThrownBy(() -> authService.signup(signUpRequest))
                .isInstanceOf(UserAlreadyRegisteredException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void signup_throwsUserException_whenRolesAreNull() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        signUpRequest.setRoles(null);
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);

        assertThatThrownBy(() -> authService.signup(signUpRequest))
                .isInstanceOf(UserException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void signup_throwsUserException_whenRolesAreEmpty() {
        SignUpRequest signUpRequest = buildSignUpRequest();
        signUpRequest.setRoles(Set.of());
        when(userRepository.existsByEmail("jdoe@example.com")).thenReturn(false);
        when(userRepository.existsByUsername("jdoe")).thenReturn(false);

        assertThatThrownBy(() -> authService.signup(signUpRequest))
                .isInstanceOf(UserException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void login_returnsLoginResultWithAccessAndRefreshToken_whenCredentialsAreValid() throws Exception {
        User user = buildUser();
        when(userRepository.findByUsername("jdoe")).thenReturn(Optional.of(user));
        when(bCryptPasswordEncoder.matches("password", "hashed-password")).thenReturn(true);
        when(mapper.rolesEntitySetToRolesDtoSet(user.getRoles())).thenReturn(Set.of(new RoleDto()));
        when(jwtHelper.generateToken(eq("jdoe"), eq("jdoe@example.com"), any())).thenReturn("access-token");

        LoginResult result = authService.login("jdoe", "password");

        assertThat(result.getUser()).isEqualTo(user);
        assertThat(result.getAuthenticationHeader().getFirst("Authorization")).isEqualTo("Bearer access-token");
        assertThat(result.getRefreshToken()).isNotBlank();

        ArgumentCaptor<RefreshToken> savedToken = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(savedToken.capture());
        assertThat(savedToken.getValue().getUsername()).isEqualTo("jdoe");
        assertThat(savedToken.getValue().isRevoked()).isFalse();
    }

    @Test
    void login_throwsUserNotExistsException_whenUsernameNotFound() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login("ghost", "password"))
                .isInstanceOf(UserNotExistsException.class);
    }

    @Test
    void login_returnsNull_whenPasswordDoesNotMatch() throws Exception {
        User user = buildUser();
        when(userRepository.findByUsername("jdoe")).thenReturn(Optional.of(user));
        when(bCryptPasswordEncoder.matches("wrong", "hashed-password")).thenReturn(false);

        LoginResult result = authService.login("jdoe", "wrong");

        assertThat(result).isNull();
    }

    @Test
    void refresh_rotatesToken_whenRefreshTokenIsActiveAndUnexpired() throws Exception {
        User user = buildUser();
        RefreshToken existingToken = new RefreshToken();
        existingToken.setToken("old-refresh-token");
        existingToken.setUsername("jdoe");
        existingToken.setRevoked(false);
        existingToken.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).plusDays(1));

        when(refreshTokenRepository.findByToken("old-refresh-token")).thenReturn(Optional.of(existingToken));
        when(refreshTokenRepository.revokeIfActive("old-refresh-token")).thenReturn(1);
        when(userRepository.findByUsername("jdoe")).thenReturn(Optional.of(user));
        when(mapper.rolesEntitySetToRolesDtoSet(user.getRoles())).thenReturn(Set.of(new RoleDto()));
        when(jwtHelper.generateToken(eq("jdoe"), eq("jdoe@example.com"), any())).thenReturn("new-access-token");

        LoginResult result = authService.refresh("old-refresh-token");

        assertThat(result.getAuthenticationHeader().getFirst("Authorization")).isEqualTo("Bearer new-access-token");
        assertThat(result.getRefreshToken()).isNotEqualTo("old-refresh-token");
        verify(refreshTokenRepository).revokeIfActive("old-refresh-token");
    }

    @Test
    void refresh_throwsRefreshTokenException_whenTokenNotRecognized() {
        when(refreshTokenRepository.findByToken("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("unknown"))
                .isInstanceOf(RefreshTokenException.class);
        verify(refreshTokenRepository, never()).revokeIfActive(anyString());
    }

    @Test
    void refresh_throwsRefreshTokenException_whenTokenIsExpired() {
        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setToken("expired-token");
        expiredToken.setUsername("jdoe");
        expiredToken.setRevoked(false);
        expiredToken.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).minusDays(1));

        when(refreshTokenRepository.findByToken("expired-token")).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> authService.refresh("expired-token"))
                .isInstanceOf(RefreshTokenException.class);
        verify(refreshTokenRepository, never()).revokeIfActive(anyString());
    }

    @Test
    void refresh_throwsRefreshTokenException_whenConcurrentRotationLosesTheRace() {
        RefreshToken existingToken = new RefreshToken();
        existingToken.setToken("contested-token");
        existingToken.setUsername("jdoe");
        existingToken.setRevoked(false);
        existingToken.setExpiresOn(OffsetDateTime.now(ZoneOffset.UTC).plusDays(1));

        when(refreshTokenRepository.findByToken("contested-token")).thenReturn(Optional.of(existingToken));
        // Simulates another request having already rotated this token between the read and the
        // conditional update (the race M1 was written to close).
        when(refreshTokenRepository.revokeIfActive("contested-token")).thenReturn(0);

        assertThatThrownBy(() -> authService.refresh("contested-token"))
                .isInstanceOf(RefreshTokenException.class);
        verify(userRepository, never()).findByUsername(anyString());
    }

    @Test
    void logout_blacklistsAccessTokenAndRevokesActiveRefreshTokens() throws Exception {
        Claims claims = org.mockito.Mockito.mock(Claims.class);
        when(claims.getId()).thenReturn("jti-123");
        when(claims.getSubject()).thenReturn("jdoe");
        when(claims.getExpiration()).thenReturn(java.util.Date.from(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(20).toInstant()));
        when(jwtHelper.getClaimsFromToken("access-token")).thenReturn(claims);

        RefreshToken active1 = new RefreshToken();
        active1.setRevoked(false);
        RefreshToken active2 = new RefreshToken();
        active2.setRevoked(false);
        when(refreshTokenRepository.findByUsernameAndRevokedFalse("jdoe")).thenReturn(List.of(active1, active2));

        authService.logout("access-token");

        ArgumentCaptor<BlacklistedToken> blacklisted = ArgumentCaptor.forClass(BlacklistedToken.class);
        verify(blacklistedTokenRepository).save(blacklisted.capture());
        assertThat(blacklisted.getValue().getTokenId()).isEqualTo("jti-123");

        assertThat(active1.isRevoked()).isTrue();
        assertThat(active2.isRevoked()).isTrue();
        verify(refreshTokenRepository).saveAll(List.of(active1, active2));
    }
}
