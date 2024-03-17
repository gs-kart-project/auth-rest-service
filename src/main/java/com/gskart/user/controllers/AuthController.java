package com.gskart.user.controllers;

import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.LoginRequest;
import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.services.IAuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


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
            User user = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
            if(user == null){
                return unauthorizedResponse;
            }
            UserDto userDto = mapper.userEntityToDto(user);
            return ResponseEntity.ok(userDto);
        }
        catch (UserNotExistsException userNotExistsException){
            return unauthorizedResponse;
        }
    }
    /*
    TODO
     1. logout
     2. forget password
     3. Auth Token using JWT
     */
}
