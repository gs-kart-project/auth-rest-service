package com.gskart.user.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
    /*
    TODO
     1. CRUD for Roles
     2. Update, Fetch, Delete users
     3. Inactivate user
     4. Expiring credentials
     */

    @PreAuthorize("hasAuthority('Developer')")
    @GetMapping("/{id}")
    public ResponseEntity<String> getUserById(@PathVariable("id") Integer id){
        return ResponseEntity.ok("Returning user with id"+id.toString());
    }
}
