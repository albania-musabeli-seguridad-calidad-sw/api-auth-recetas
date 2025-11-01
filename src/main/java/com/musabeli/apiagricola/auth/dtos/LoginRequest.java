package com.musabeli.apiagricola.auth.dtos;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest (

        @NotBlank(message = "El usuario es obligatorio")
        String username,

        @NotBlank(message = "La contraseña es obligatoria")
        String password
){}
