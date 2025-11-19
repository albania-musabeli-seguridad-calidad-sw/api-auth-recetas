package com.musabeli.apiagricola.auth.services;

import com.musabeli.apiagricola.auth.dtos.UserResponse;
import com.musabeli.apiagricola.auth.dtos.UserUpdateRequest;
import com.musabeli.apiagricola.auth.entities.User;
import com.musabeli.apiagricola.auth.repository.UserRepository;
import com.musabeli.apiagricola.auth.security.JWTAuthenticationConfig;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JWTAuthenticationConfig jwtConfig;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public String register(String username, String email, String rawPassword) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Usuario ya existe");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email ya registrado");
        }

        String encodedPassword = passwordEncoder.encode(rawPassword);

        User user = User.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .enabled(true)
                .build();

        userRepository.save(user);
        return "Usuario registrado";
    }

    public String login(String username, String rawPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            //throw new RuntimeException("Contraseña incorrecta");
            throw new BadCredentialsException("Contreña incorrecta"); // es más especifica al caso
        }

        return jwtConfig.getJWTToken(username);
    }

    // Spring Security
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
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
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado con id: " + id));
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail());
    }


    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        
        // Seguridad: solo puede editar su propia cuenta
        if (!user.getUsername().equals(currentUsername)) {
            throw new RuntimeException("No tienes permiso para modificar este usuario");
        }
        
        if (request.username() != null && !request.username().isBlank()) {
            if (!request.username().equals(user.getUsername()) &&
                    userRepository.existsByUsername(request.username())) {
                throw new RuntimeException("El nombre de usuario ya está en uso");
            }
            user.setUsername(request.username().trim());
        }
        
        if (request.email() != null && !request.email().isBlank()) {
            if (!request.email().equals(user.getEmail()) &&
                    userRepository.existsByEmail(request.email())) {
                throw new RuntimeException("El email ya está registrado");
            }
            user.setEmail(request.email().trim());
        }
        
        if (request.password() != null && !request.password().isBlank()) {
            user.setPassword(passwordEncoder.encode(request.password()));
        }
        
        user = userRepository.save(user);
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail());
    }


    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!user.getUsername().equals(currentUsername)) {
            throw new RuntimeException("No tiene permiso para eliminar este usuario");
        }

        userRepository.delete(user);
    }


}