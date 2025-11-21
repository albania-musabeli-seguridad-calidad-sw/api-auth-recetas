package com.musabeli.apiagricola.exceptions.global;


import com.musabeli.apiagricola.exceptions.EmailAlreadyExistsException;
import com.musabeli.apiagricola.exceptions.ResourceNotFoundException;
import com.musabeli.apiagricola.exceptions.UnauthorizedActionException;
import com.musabeli.apiagricola.exceptions.UserAlreadyExistsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {

    record ErrorResponse(String message, String error, int status, String timestamp) {}

    private ProblemDetail build(String message, HttpStatus status) {
        ProblemDetail pd = ProblemDetail.forStatus(status);
        pd.setTitle(status.getReasonPhrase());
        pd.setProperty("timestamp", LocalDateTime.now());
        pd.setProperty("message", message);
        return pd;
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(404).body(build(ex.getMessage(), HttpStatus.NOT_FOUND));
    }

    @ExceptionHandler({UserAlreadyExistsException.class, EmailAlreadyExistsException.class})
    public ResponseEntity<ProblemDetail> handleConflict(RuntimeException ex) {
        return ResponseEntity.status(409).body(build(ex.getMessage(), HttpStatus.CONFLICT));
    }

    @ExceptionHandler(UnauthorizedActionException.class)
    public ResponseEntity<ProblemDetail> handleForbidden(UnauthorizedActionException ex) {
        return ResponseEntity.status(403).body(build(ex.getMessage(), HttpStatus.FORBIDDEN));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(RuntimeException ex) {
        return ResponseEntity.status(500)
                .body(build("Error interno del servidor", HttpStatus.INTERNAL_SERVER_ERROR));
    }

}
