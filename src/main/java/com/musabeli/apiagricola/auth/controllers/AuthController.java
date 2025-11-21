package com.musabeli.apiagricola.auth.controllers;

import com.musabeli.apiagricola.auth.dtos.LoginRequest;
import com.musabeli.apiagricola.auth.dtos.LoginResponse;
import com.musabeli.apiagricola.auth.dtos.RegisterRequest;
import com.musabeli.apiagricola.auth.dtos.RegisterResponse;
import com.musabeli.apiagricola.auth.services.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService){
        this.userService = userService;
    }

    // REGISTRO
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        userService.register(
                request.username(),
                request.email(),
                request.password()
        );

        RegisterResponse response = new RegisterResponse(
                "Usuario registrado con éxito",
                request.username(),
                request.email()
        );

        return ResponseEntity.ok(response);
    }

    // === LOGIN ===
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        String token = userService.login(request.username(), request.password());

        LoginResponse response = new LoginResponse(
                token,
                "Login exitoso",
                request.username()
        );

        return ResponseEntity.ok(response);
    }
}
