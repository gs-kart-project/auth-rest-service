package com.gskart.user.services;

import com.gskart.user.DTOs.requests.SignUpRequest;
import com.gskart.user.DTOs.requests.UpdateUserRequest;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserNotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IUserService {
    User register(SignUpRequest signUpRequest) throws UserAlreadyRegisteredException;

    User getUser(Long id) throws UserNotFoundException;

    Page<User> listUsers(Pageable pageable);

    User updateUser(Long id, UpdateUserRequest updateUserRequest, String modifiedBy)
            throws UserNotFoundException, UserAlreadyRegisteredException;

    void inactivateUser(Long id, String modifiedBy) throws UserNotFoundException;
}
