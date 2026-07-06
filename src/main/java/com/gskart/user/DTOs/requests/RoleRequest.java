package com.gskart.user.DTOs.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RoleRequest {
    @NotBlank
    private String name;
    private String description;
}
