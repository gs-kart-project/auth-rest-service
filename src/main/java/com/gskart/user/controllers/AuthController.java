package com.gskart.user.controllers;

import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.LoginRequest;
import com.gskart.user.DTOs.requests.RefreshTokenRequest;
import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.response.ClaimsResponse;
import com.gskart.user.DTOs.response.LoginResponse;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.*;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.services.IAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.atomic.AtomicBoolean;


/**
 * End points to facilitate Authorization and Authentication activities
 * TODO Add a Controller advice to handle generic exceptions
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    final IAuthService authService;
    final Mapper mapper;

    public AuthController(IAuthService authService, Mapper mapper){

        this.authService = authService;
        this.mapper = mapper;
    }

    /**
     * Sign Up API - Creates a new user with the details provided
     * @param signUpRequest
     * @return the user details as per UserDto if successfully signed up.
     * @throws UserException when there is any other expectations not met for the user request.
     * @throws UserAlreadyRegisteredException when the user is already registered (Checks using email and username)
     */
    // sign up
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpRequest signUpRequest) throws UserException, UserAlreadyRegisteredException {
        User user = authService.signup(signUpRequest);
        UserDto userDto = mapper.userEntityToDto(user);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Login with the given credentials
     * @param loginRequest
     * @return the access token in the Authorization header, and the user + refresh token in the body.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        ResponseEntity<LoginResponse> unauthorizedResponse = ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        try {
            LoginResult loginResult = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
            if(loginResult == null || loginResult.getUser() == null){
                return unauthorizedResponse;
            }
            if(loginResult.getAuthenticationHeader().isEmpty()){
                return unauthorizedResponse;
            }
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setUser(mapper.userEntityToDto(loginResult.getUser()));
            loginResponse.setRefreshToken(loginResult.getRefreshToken());
            return ResponseEntity.ok()
                    .headers(loginResult.getAuthenticationHeader())
                    .body(loginResponse);
        }
        catch (UserNotExistsException userNotExistsException){
            log.warn("Login failed: {}", userNotExistsException.getMessage());
            return unauthorizedResponse;
        } catch (JwtKeyStoreException e) {
            log.error("Login failed due to a JWT keystore error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Exchange a valid refresh token for a new access token (rotates the refresh token).
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            LoginResult loginResult = authService.refresh(refreshTokenRequest.getRefreshToken());
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setUser(mapper.userEntityToDto(loginResult.getUser()));
            loginResponse.setRefreshToken(loginResult.getRefreshToken());
            return ResponseEntity.ok()
                    .headers(loginResult.getAuthenticationHeader())
                    .body(loginResponse);
        } catch (RefreshTokenException e) {
            log.warn("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (JwtKeyStoreException e) {
            log.error("Token refresh failed due to a JWT keystore error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Logs out the caller: blacklists the current access token and revokes their refresh tokens.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        String accessToken = authHeader.substring(7);
        try {
            authService.logout(accessToken);
            return ResponseEntity.ok().build();
        } catch (JwtKeyStoreException e) {
            log.error("Logout failed due to a JWT keystore error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (JwtNotValidException e) {
            log.warn("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("token/validate")
    public ResponseEntity<Boolean> validateToken(@RequestBody UserDto userDto){
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(!userDetails.getUsername().equals(userDto.getUsername())){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }
        AtomicBoolean containsAuthority = new AtomicBoolean(false);
        userDetails.getAuthorities().forEach(authority -> userDto.getRoles().forEach(role -> {
            if(authority.getAuthority().contains(role.getName())){
                containsAuthority.set(true);
            }
        }));
        if(containsAuthority.get()){
            return ResponseEntity.ok(true);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
    }

    @GetMapping("/token/claims")
    public ResponseEntity<ClaimsResponse> getClaimsFromToken(){
        GSKartUserDetails userDetails = (GSKartUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userDetails.getUserEntity();
        ClaimsResponse response = mapper.userEntityToClaimsResponse(user);
        return ResponseEntity.ok(response);
    }
    // TODO forget password (FR-U5, depends on notifications-service)

}
