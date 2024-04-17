package com.gskart.user.controllers;

import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.LoginRequest;
import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.response.ClaimsResponse;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.*;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.services.IAuthService;
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
     * TODO response should be of type LoginResponse. Need to check and change after adding token based auth
     * @param loginRequest
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequest loginRequest) {
        var unauthorizedResponse = new ResponseEntity<UserDto>(HttpStatus.UNAUTHORIZED);
        try {
            LoginResult loginResult = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
            if(loginResult == null || loginResult.getUser() == null){
                return unauthorizedResponse;
            }
            if(loginResult.getAuthenticationHeader().isEmpty()){
                return unauthorizedResponse;
            }
            UserDto userDto = mapper.userEntityToDto(loginResult.getUser());
            ResponseEntity<UserDto> response = new ResponseEntity<>(userDto, loginResult.getAuthenticationHeader(), HttpStatus.OK);
            return response;
        }
        catch (UserNotExistsException userNotExistsException){
            userNotExistsException.printStackTrace();
            return unauthorizedResponse;
        } catch (JwtKeyStoreException e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("token/validate")
    public ResponseEntity<Boolean> validateToken(@RequestBody UserDto userDto, @RequestHeader(value = "Authorization") String authHeader){
        /*ResponseEntity<Boolean> unauthorizedResponse = new ResponseEntity<>(false, HttpStatus.UNAUTHORIZED);
        if(authHeader == null || authHeader.isEmpty() || !authHeader.startsWith("Bearer ")){
            return unauthorizedResponse;
        }

        if(userDto == null){
            return new ResponseEntity<>(false, HttpStatus.BAD_REQUEST);
        }

        String token = authHeader.substring(7);
        Set<Role> roles = mapper.rolesDtoSetToRolesEntitySet(userDto.getRoles());
        try {
            isTokenValid = authService.validateToken(
                    token,
                    userDto.getUsername()
            );
        } catch (JwtKeyStoreException e) {
            e.printStackTrace();
            return new ResponseEntity<>(false, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        if(!isTokenValid){
            return new ResponseEntity<>(false, HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>(isTokenValid, HttpStatus.OK);*/
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
        /*if(authHeader == null || authHeader.isEmpty() || !authHeader.startsWith("Bearer ")){
            // No bearer token present in header
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        var token = authHeader.substring(7);
        try {
            var claims = authService.getClaimsFromToken(token);
            ClaimsResponse response = mapper.claimsToClaimsResponse(claims);
            return ResponseEntity.ok(response);
        } catch (JwtNotValidException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        } catch (JwtKeyStoreException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        catch (ClassCastException e){
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }*/
        GSKartUserDetails userDetails = (GSKartUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userDetails.getUserEntity();
        ClaimsResponse response = mapper.userEntityToClaimsResponse(user);
        return ResponseEntity.ok(response);
    }
    /*
    TODO
     1. logout
     2. forget password
     */

}
