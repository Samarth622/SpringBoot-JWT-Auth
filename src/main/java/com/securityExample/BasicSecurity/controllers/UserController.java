package com.securityExample.BasicSecurity.controllers;

import com.securityExample.BasicSecurity.dto.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    DataSource dataSource;

    @PostMapping("/sign-up")
    public String createUser(@RequestParam String username, @RequestParam String password, @RequestParam String role){

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        if(jdbcUserDetailsManager.userExists(username)){
            return "User Already Exits";
        }

        UserDetails userDetails = User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles(role)
                .build();

        jdbcUserDetailsManager.createUser(userDetails);
        return "User Created Successfully!!";
    }

    @GetMapping("/getProfile")
    public ResponseEntity<?> getUserProfile(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> user = new HashMap<>();
        user.put("username", userDetails.getUsername());
        user.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList())
        );
        user.put("message", "This is user-specific content from backend.");
        return ResponseEntity.ok(user);
    }
}
