package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.*;
import io.jsonwebtoken.Claims;

public interface IAuthService {
    User signup(SignUpRequest signUpRequest) throws UserException, UserAlreadyRegisteredException;
    LoginResult login(String username, String password) throws UserNotExistsException, JwtKeyStoreException;

    Claims getClaimsFromToken(String token) throws JwtNotValidException, JwtKeyStoreException;

    LoginResult refresh(String refreshToken) throws RefreshTokenException, JwtKeyStoreException;

    void logout(String accessToken) throws JwtKeyStoreException, JwtNotValidException;
}
