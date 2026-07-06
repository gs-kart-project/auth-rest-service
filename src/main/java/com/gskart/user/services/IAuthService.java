package com.gskart.user.services;

import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.exceptions.*;
import io.jsonwebtoken.Claims;

public interface IAuthService {
    LoginResult login(String username, String password) throws UserNotExistsException, JwtKeyStoreException;

    Claims getClaimsFromToken(String token) throws JwtNotValidException, JwtKeyStoreException;

    LoginResult refresh(String refreshToken) throws RefreshTokenException, JwtKeyStoreException;

    void logout(String accessToken) throws JwtKeyStoreException, JwtNotValidException;
}
