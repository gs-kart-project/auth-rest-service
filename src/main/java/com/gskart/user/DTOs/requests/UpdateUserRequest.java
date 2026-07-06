package com.gskart.user.DTOs.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserRequest {
    @NotBlank
    private String firstname;
    @NotBlank
    private String lastname;
    @NotBlank
    @Email
    private String email;
}
