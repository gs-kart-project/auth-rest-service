package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;

public interface IAuthService {
    User signup(SignUpRequest signUpRequest) throws UserException, UserAlreadyRegisteredException;
    User login(String username, String password) throws UserNotExistsException;
}
