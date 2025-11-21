package com.musabeli.apiagricola.auth.services;

import com.musabeli.apiagricola.auth.dtos.UserResponse;
import com.musabeli.apiagricola.auth.dtos.UserUpdateRequest;
import com.musabeli.apiagricola.auth.entities.User;
import com.musabeli.apiagricola.auth.repository.UserRepository;
import com.musabeli.apiagricola.auth.security.JWTAuthenticationConfig;
import com.musabeli.apiagricola.exceptions.EmailAlreadyExistsException;
import com.musabeli.apiagricola.exceptions.ResourceNotFoundException;
import com.musabeli.apiagricola.exceptions.UnauthorizedActionException;
import com.musabeli.apiagricola.exceptions.UserAlreadyExistsException;
import jakarta.transaction.Transactional;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private static final String MSG_USER_NOT_FOUND = "Usuario no encontrado";

    private final UserRepository userRepository;
    private final JWTAuthenticationConfig jwtConfig;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    public UserService(UserRepository userRepository,
                       JWTAuthenticationConfig jwtConfig) {
        this.userRepository = userRepository;
        this.jwtConfig = jwtConfig;
    }


    @Transactional
    public String register(String username, String email, String rawPassword) {
        if (userRepository.existsByUsername(username)) {
            throw new UserAlreadyExistsException("El usuario '" + username + "' ya existe");
        }
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException("El email '" + email + "' ya está registrado");
        }

        String encodedPassword = passwordEncoder.encode(rawPassword);

        User user = User.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .enabled(true)
                .build();

        userRepository.save(user);
        return "Usuario registrado correctamente";
    }

    public String login(String username, String rawPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(MSG_USER_NOT_FOUND));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("Contraseña incorrecta");
        }

        return jwtConfig.getJWTToken(username);
    }

    // Spring Security
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(MSG_USER_NOT_FOUND + ": " + username));
    }

    // encriptar
    public PasswordEncoder passwordEncoder() {
        return passwordEncoder;
    }

    public List<UserResponse> getAllUsers(){
        return userRepository.findAll().stream()
                .map(user -> new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail()
                ))
                .toList();
    }


    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException(MSG_USER_NOT_FOUND + " con id: " + id));
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail());
    }


    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException(MSG_USER_NOT_FOUND));
        
        // Seguridad: solo puede editar su propia cuenta
        if (!user.getUsername().equals(currentUsername)) {
            throw new UnauthorizedActionException("No tienes permiso para modificar este usuario");
        }

        if (request.username() != null && !request.username().isBlank()) {
            String newUsername = request.username().trim();
            if (!newUsername.equals(user.getUsername()) && userRepository.existsByUsername(newUsername)) {
                throw new UserAlreadyExistsException("El nombre de usuario '" + newUsername + "' ya está en uso");
            }
            user.setUsername(newUsername);
        }

        if (request.email() != null && !request.email().isBlank()) {
            String newEmail = request.email().trim();
            if (!newEmail.equals(user.getEmail()) && userRepository.existsByEmail(newEmail)) {
                throw new EmailAlreadyExistsException("El email '" + newEmail + "' ya está registrado");
            }
            user.setEmail(newEmail);
        }

        if (request.password() != null && !request.password().isBlank()) {
            user.setPassword(passwordEncoder.encode(request.password()));
        }
        
        userRepository.save(user);
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail());
    }


    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException(MSG_USER_NOT_FOUND));

        if (!user.getUsername().equals(currentUsername)) {
            throw new UnauthorizedActionException("No tiene permiso para eliminar este usuario");
        }

        userRepository.delete(user);
    }
}