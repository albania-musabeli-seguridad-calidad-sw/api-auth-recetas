package com.musabeli.apiagricola.auth.dtos;

public record LoginResponse (

        String token,
        String message,
        String username
){}
