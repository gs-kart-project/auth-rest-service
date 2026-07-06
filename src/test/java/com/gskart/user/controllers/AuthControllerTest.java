package com.gskart.user.controllers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.TokenRequest;
import com.gskart.user.DTOs.response.ClaimsResponse;
import com.gskart.user.DTOs.response.IntrospectionResponse;
import com.gskart.user.DTOs.response.TokenResponse;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.exceptions.RefreshTokenException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.services.IAuthService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private IAuthService authService;
    @Mock
    private Mapper mapper;

    private AuthController authController;

    @BeforeEach
    void setUp() {
        authController = new AuthController(authService, mapper, 20L);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private User buildUserWithRole(String username, String roleName) {
        User user = new User();
        user.setUsername(username);
        Role role = new Role();
        role.setName(roleName);
        user.setRoles(Set.of(role));
        return user;
    }

    private void authenticateAs(User user) {
        GSKartUserDetails userDetails = new GSKartUserDetails(user);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
    }

    private LoginResult buildLoginResult() {
        LoginResult loginResult = new LoginResult();
        loginResult.setUser(new User());
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer access-token");
        loginResult.setAuthenticationHeader(headers);
        loginResult.setRefreshToken("refresh-token");
        return loginResult;
    }

    private TokenRequest passwordGrantRequest(String username, String password) {
        TokenRequest request = new TokenRequest();
        request.setGrantType("password");
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }

    private TokenRequest refreshGrantRequest(String refreshToken) {
        TokenRequest request = new TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken(refreshToken);
        return request;
    }

    @Test
    void token_returnsAccessAndRefreshToken_whenPasswordGrantIsValid() throws Exception {
        when(authService.login("jdoe", "password")).thenReturn(buildLoginResult());

        ResponseEntity<TokenResponse> response = authController.token(passwordGrantRequest("jdoe", "password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getAccessToken()).isEqualTo("access-token");
        assertThat(response.getBody().getTokenType()).isEqualTo("Bearer");
        assertThat(response.getBody().getExpiresIn()).isEqualTo(1200L);
        assertThat(response.getBody().getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void token_throwsUserException_whenPasswordGrantIsMissingCredentials() {
        TokenRequest request = passwordGrantRequest(null, null);

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(UserException.class);
    }

    @Test
    void token_throwsUserNotExistsException_whenUserDoesNotExist() throws Exception {
        TokenRequest request = passwordGrantRequest("ghost", "password");
        when(authService.login(anyString(), anyString())).thenThrow(new UserNotExistsException("not found"));

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(UserNotExistsException.class);
    }

    @Test
    void token_throwsUserNotExistsException_whenLoginResultIsNull() throws Exception {
        TokenRequest request = passwordGrantRequest("jdoe", "wrong");
        when(authService.login(anyString(), anyString())).thenReturn(null);

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(UserNotExistsException.class);
    }

    @Test
    void token_propagatesJwtKeyStoreException_whenKeystoreFails() throws Exception {
        TokenRequest request = passwordGrantRequest("jdoe", "password");
        when(authService.login(anyString(), anyString())).thenThrow(new JwtKeyStoreException("keystore error"));

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(JwtKeyStoreException.class);
    }

    @Test
    void token_returnsRotatedTokens_whenRefreshTokenGrantIsValid() throws Exception {
        when(authService.refresh("old-refresh-token")).thenReturn(buildLoginResult());

        ResponseEntity<TokenResponse> response = authController.token(refreshGrantRequest("old-refresh-token"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void token_throwsUserException_whenRefreshTokenGrantIsMissingRefreshToken() {
        TokenRequest request = refreshGrantRequest(null);

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(UserException.class);
    }

    @Test
    void token_propagatesRefreshTokenException_whenRefreshTokenIsExpiredOrRevoked() throws Exception {
        TokenRequest request = refreshGrantRequest("bad-token");
        when(authService.refresh(anyString())).thenThrow(new RefreshTokenException("expired"));

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(RefreshTokenException.class);
    }

    @Test
    void token_throwsUserException_whenGrantTypeIsUnsupported() {
        TokenRequest request = new TokenRequest();
        request.setGrantType("client_credentials");

        assertThatThrownBy(() -> authController.token(request)).isInstanceOf(UserException.class);
    }

    @Test
    void revoke_returns204_whenAccessTokenIsValid() throws Exception {
        ResponseEntity<Void> response = authController.revoke("Bearer valid-access-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void revoke_propagatesJwtNotValidException_whenAccessTokenIsNotValid() throws Exception {
        org.mockito.Mockito.doThrow(new JwtNotValidException("invalid", new RuntimeException()))
                .when(authService).logout(anyString());

        assertThatThrownBy(() -> authController.revoke("Bearer invalid-access-token"))
                .isInstanceOf(JwtNotValidException.class);
    }

    @Test
    void revoke_propagatesJwtKeyStoreException_whenKeystoreFails() throws Exception {
        org.mockito.Mockito.doThrow(new JwtKeyStoreException("keystore error"))
                .when(authService).logout(anyString());

        assertThatThrownBy(() -> authController.revoke("Bearer some-access-token"))
                .isInstanceOf(JwtKeyStoreException.class);
    }

    @Test
    void revoke_throwsJwtNotValidException_whenAuthorizationHeaderIsMissing() {
        assertThatThrownBy(() -> authController.revoke(null)).isInstanceOf(JwtNotValidException.class);
    }

    @Test
    void revoke_throwsJwtNotValidException_whenAuthorizationHeaderIsMalformed() {
        assertThatThrownBy(() -> authController.revoke("not-a-bearer-token"))
                .isInstanceOf(JwtNotValidException.class);
    }

    @Test
    void introspect_returnsActiveTrue_whenUsernameAndAuthorityMatch() {
        User user = buildUserWithRole("jdoe", "USER");
        authenticateAs(user);

        UserDto userDto = new UserDto();
        userDto.setUsername("jdoe");
        RoleDto roleDto = new RoleDto();
        roleDto.setName("USER");
        userDto.setRoles(Set.of(roleDto));

        ResponseEntity<IntrospectionResponse> response = authController.introspect(userDto);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().isActive()).isTrue();
    }

    @Test
    void introspect_returnsActiveFalse_whenUsernameDoesNotMatchPrincipal() {
        User user = buildUserWithRole("jdoe", "USER");
        authenticateAs(user);

        UserDto userDto = new UserDto();
        userDto.setUsername("someone-else");
        RoleDto roleDto = new RoleDto();
        roleDto.setName("USER");
        userDto.setRoles(Set.of(roleDto));

        ResponseEntity<IntrospectionResponse> response = authController.introspect(userDto);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().isActive()).isFalse();
    }

    @Test
    void introspect_returnsActiveFalse_whenRolesAreNull() {
        User user = buildUserWithRole("jdoe", "USER");
        authenticateAs(user);

        UserDto userDto = new UserDto();
        userDto.setUsername("jdoe");
        userDto.setRoles(null);

        ResponseEntity<IntrospectionResponse> response = authController.introspect(userDto);

        assertThat(response.getBody().isActive()).isFalse();
    }

    @Test
    void userInfo_returnsClaims_whenPrincipalIsAuthenticated() {
        User user = buildUserWithRole("jdoe", "USER");
        authenticateAs(user);

        ClaimsResponse claimsResponse = new ClaimsResponse();
        claimsResponse.setUsername("jdoe");
        when(mapper.userEntityToClaimsResponse(user)).thenReturn(claimsResponse);

        ResponseEntity<ClaimsResponse> response = authController.userInfo();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(claimsResponse);
    }
}
