package com.gskart.user.DTOs.results;

import com.gskart.user.entities.User;
import lombok.Data;
import org.springframework.http.HttpHeaders;

@Data
public class LoginResult {
    private User user;
    private HttpHeaders authenticationHeader;
}
