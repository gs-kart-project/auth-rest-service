package com.gskart.user.exceptionHandlers;

import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.exceptions.RefreshTokenException;
import com.gskart.user.exceptions.RoleAlreadyExistsException;
import com.gskart.user.exceptions.RoleNotFoundException;
import com.gskart.user.exceptions.UserAlreadyRegisteredException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.exceptions.UserNotFoundException;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleAlreadyExists_returns409_forUserAlreadyRegistered() {
        ProblemDetail problemDetail = handler.handleAlreadyExists(new UserAlreadyRegisteredException("dup email"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
        assertThat(problemDetail.getDetail()).isEqualTo("dup email");
    }

    @Test
    void handleAlreadyExists_returns409_forRoleAlreadyExists() {
        ProblemDetail problemDetail = handler.handleAlreadyExists(new RoleAlreadyExistsException("dup role"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
    }

    @Test
    void handleNotFound_returns404_forUserNotFound() {
        ProblemDetail problemDetail = handler.handleNotFound(new UserNotFoundException("no such user"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.NOT_FOUND.value());
    }

    @Test
    void handleNotFound_returns404_forRoleNotFound() {
        ProblemDetail problemDetail = handler.handleNotFound(new RoleNotFoundException("no such role"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.NOT_FOUND.value());
    }

    @Test
    void handleUserException_returns400() {
        ProblemDetail problemDetail = handler.handleUserException(new UserException("bad request"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problemDetail.getDetail()).isEqualTo("bad request");
    }

    @Test
    void handleAuthenticationFailure_returns401_forEachAuthExceptionType() {
        assertThat(handler.handleAuthenticationFailure(new UserNotExistsException("x")).getStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(handler.handleAuthenticationFailure(new RefreshTokenException("x")).getStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(handler.handleAuthenticationFailure(new JwtNotValidException("x", new RuntimeException())).getStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void handleAccessDenied_returns403_withGenericMessage() {
        ProblemDetail problemDetail = handler.handleAccessDenied(new AccessDeniedException("secret detail"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(problemDetail.getDetail()).doesNotContain("secret detail");
    }

    @Test
    void handleDataIntegrityViolation_returns409_withGenericMessage() {
        ProblemDetail problemDetail = handler.handleDataIntegrityViolation(
                new DataIntegrityViolationException("Duplicate entry 'ADMIN' for key 'UK_Roles_Name'"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
        assertThat(problemDetail.getDetail()).doesNotContain("UK_Roles_Name");
    }

    @Test
    void handleJwtKeyStoreException_returns500_withGenericMessage() {
        ProblemDetail problemDetail = handler.handleJwtKeyStoreException(new JwtKeyStoreException("secret detail"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(problemDetail.getDetail()).doesNotContain("secret detail");
    }

    @Test
    void handleUnexpectedException_returns500_withGenericMessage() {
        ProblemDetail problemDetail = handler.handleUnexpectedException(new RuntimeException("internal detail"));

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(problemDetail.getDetail()).doesNotContain("internal detail");
    }

    @Test
    void handleMethodArgumentNotValid_returns400_withFieldErrors() throws NoSuchMethodException {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "target");
        bindingResult.addError(new org.springframework.validation.FieldError("target", "username", "must not be blank"));

        MethodParameter methodParameter = new MethodParameter(
                GlobalExceptionHandlerTest.class.getDeclaredMethod("dummyTarget", String.class), 0);
        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(methodParameter, bindingResult);

        ResponseEntity<Object> response = handler.handleMethodArgumentNotValid(
                exception, new HttpHeaders(), HttpStatus.BAD_REQUEST, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ProblemDetail body = (ProblemDetail) response.getBody();
        assertThat(body.getDetail()).isEqualTo("Validation failed");
        @SuppressWarnings("unchecked")
        List<String> errors = (List<String>) body.getProperties().get("errors");
        assertThat(errors).contains("username: must not be blank");
    }

    @SuppressWarnings("unused")
    private void dummyTarget(String username) {
    }
}
