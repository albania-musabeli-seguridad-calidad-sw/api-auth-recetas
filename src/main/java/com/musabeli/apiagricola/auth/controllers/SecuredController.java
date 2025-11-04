package com.musabeli.apiagricola.auth.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SecuredController {

    @GetMapping("/greetings")
    public String greetings(
            @RequestParam(value = "name", defaultValue = "World") String name,
            Authentication authentication) {

        String username = authentication.getName();
        return "Hello {" + name + "}, autenticado como: " + username;
    }
}
