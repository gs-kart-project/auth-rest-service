package com.gskart.user.DTOs.response;

import lombok.Data;

@Data
public class IntrospectionResponse {
    private boolean active;
    private String username;
}
