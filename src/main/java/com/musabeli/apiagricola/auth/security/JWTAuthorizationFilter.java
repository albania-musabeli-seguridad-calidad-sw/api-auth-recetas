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

@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JWTAuthorizationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = extractJwtFromRequest(request);

        log.debug("JWT FILTER ACTIVADO");
        log.debug("URL solicitada: {} {} ", request.getMethod(), request.getRequestURI());
        if (log.isDebugEnabled()) {
            log.debug("Header Authorization: {}", request.getHeader(JwtConstants.HEADER_AUTHORIZACION_KEY));
        }
        log.debug("Token presente: {}", jwtToken != null ? "SÍ" : "NO");

        if (jwtToken != null) {
            boolean valido = validateToken(jwtToken);
            log.debug("Token válido: {}", valido);

            if (valido) {
                String username = getUsernameFromToken(jwtToken);
                log.debug("Usuario autenticado: {}", username);
            }
        } else {
            log.debug("No se encontró token en el header");
        }
        log.debug("=====================================");


        try {
            if (jwtToken != null && validateToken(jwtToken)) {
                String username = getUsernameFromToken(jwtToken);
                List<String> authorities = getAuthoritiesFromToken(jwtToken);

                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null,
                        authorities.stream().map(SimpleGrantedAuthority::new).toList()
                );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    // EXTRAER TOKEN
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(JwtConstants.HEADER_AUTHORIZACION_KEY);
        if (bearerToken != null && bearerToken.startsWith(JwtConstants.TOKEN_BEARER_PREFIX)) {
            return bearerToken.substring(7); // sin el "Bearer "
        }
        return null;
    }

    // VALIDAR TOKEN
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

    // OBTENER USUARIO
    private String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) JwtConstants.getSigningKey(JwtConstants.SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    // OBTENER ROLES
    private List<String> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) JwtConstants.getSigningKey(JwtConstants.SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return (List<String>) claims.get("authorities");
    }
}
