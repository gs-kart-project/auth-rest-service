package com.gskart.user.controllers;

import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.LoginRequest;
import com.gskart.user.DTOs.requests.RefreshTokenRequest;
import com.gskart.user.DTOs.response.LoginResponse;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.exceptions.RefreshTokenException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IAuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
        authController = new AuthController(authService, mapper);
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

    @Test
    void login_returns200WithAuthorizationHeader_whenCredentialsAreValid() throws Exception {
        when(authService.login("jdoe", "password")).thenReturn(buildLoginResult());
        when(mapper.userEntityToDto(any())).thenReturn(new UserDto());

        ResponseEntity<LoginResponse> response = authController.login(loginRequest("jdoe", "password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst("Authorization")).isEqualTo("Bearer access-token");
        assertThat(response.getBody().getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void login_returns401_whenUserDoesNotExist() throws Exception {
        when(authService.login(anyString(), anyString())).thenThrow(new UserNotExistsException("not found"));

        ResponseEntity<LoginResponse> response = authController.login(loginRequest("ghost", "password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void login_returns401_whenLoginResultIsNull() throws Exception {
        when(authService.login(anyString(), anyString())).thenReturn(null);

        ResponseEntity<LoginResponse> response = authController.login(loginRequest("jdoe", "wrong"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void login_returns500_whenKeystoreFails() throws Exception {
        when(authService.login(anyString(), anyString())).thenThrow(new JwtKeyStoreException("keystore error"));

        ResponseEntity<LoginResponse> response = authController.login(loginRequest("jdoe", "password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void refresh_returns200WithRotatedTokens_whenRefreshTokenIsValid() throws Exception {
        when(authService.refresh("old-refresh-token")).thenReturn(buildLoginResult());
        when(mapper.userEntityToDto(any())).thenReturn(new UserDto());

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("old-refresh-token");

        ResponseEntity<LoginResponse> response = authController.refresh(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void refresh_returns401_whenRefreshTokenIsExpiredOrRevoked() throws Exception {
        when(authService.refresh(anyString())).thenThrow(new RefreshTokenException("expired"));

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("bad-token");

        ResponseEntity<LoginResponse> response = authController.refresh(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void refresh_returns500_whenKeystoreFails() throws Exception {
        when(authService.refresh(anyString())).thenThrow(new JwtKeyStoreException("keystore error"));

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("some-token");

        ResponseEntity<LoginResponse> response = authController.refresh(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void logout_returns200_whenAccessTokenIsValid() throws Exception {
        ResponseEntity<Void> response = authController.logout("Bearer valid-access-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void logout_returns401_whenAccessTokenIsNotValid() throws Exception {
        org.mockito.Mockito.doThrow(new JwtNotValidException("invalid", new RuntimeException()))
                .when(authService).logout(anyString());

        ResponseEntity<Void> response = authController.logout("Bearer invalid-access-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void logout_returns500_whenKeystoreFails() throws Exception {
        org.mockito.Mockito.doThrow(new JwtKeyStoreException("keystore error"))
                .when(authService).logout(anyString());

        ResponseEntity<Void> response = authController.logout("Bearer some-access-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private LoginRequest loginRequest(String username, String password) {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(username);
        loginRequest.setPassword(password);
        return loginRequest;
    }
}
