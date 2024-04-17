package com.gskart.user.DTOs.results;

import com.gskart.user.entities.User;
import lombok.Data;
import org.springframework.util.MultiValueMap;

@Data
public class LoginResult {
    private User user;
    private MultiValueMap<String, String> authenticationHeader;
}
