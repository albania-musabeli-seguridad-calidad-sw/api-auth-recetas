package com.musabeli.apiagricola.auth.security;

import com.musabeli.apiagricola.auth.config.JwtConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {


        System.out.println("=== JWT FILTER ACTIVADO ===");
        System.out.println("URL solicitada: " + request.getMethod() + " " + request.getRequestURI());
        System.out.println("Header Authorization: " + request.getHeader(JwtConstants.HEADER_AUTHORIZACION_KEY));

        String jwtToken = extractJwtFromRequest(request);
        System.out.println("Token extraído: " + (jwtToken != null ? "SÍ" : "NO"));

        if (jwtToken != null) {
            boolean valido = validateToken(jwtToken);
            System.out.println("Token válido: " + valido);
            if (valido) {
                String username = getUsernameFromToken(jwtToken);
                System.out.println("Usuario autenticado: " + username);
            }
        } else {
            System.out.println("No se encontró token en el header");
        }
        System.out.println("=====================================");


        try {
            //String jwtToken = extractJwtFromRequest(request);

            if (jwtToken != null && validateToken(jwtToken)) {
                String username = getUsernameFromToken(jwtToken);
                List<String> authorities = getAuthoritiesFromToken(jwtToken);

                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null,
                        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    // === EXTRAER TOKEN ===
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(JwtConstants.HEADER_AUTHORIZACION_KEY);
        if (bearerToken != null && bearerToken.startsWith(JwtConstants.TOKEN_BEARER_PREFIX)) {
            return bearerToken.substring(7); // Quita "Bearer "
        }
        return null;
    }

    // === VALIDAR TOKEN ===
    private boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith((SecretKey) JwtConstants.getSigningKey(JwtConstants.SUPER_SECRET_KEY))
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // === OBTENER USUARIO ===
    private String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) JwtConstants.getSigningKey(JwtConstants.SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    // === OBTENER ROLES ===
    private List<String> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) JwtConstants.getSigningKey(JwtConstants.SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return (List<String>) claims.get("authorities");
    }
}
