package com.musabeli.apiagricola.auth.dtos;

public record UserResponse(
        Long id,
        String username,
        String email
) {}
