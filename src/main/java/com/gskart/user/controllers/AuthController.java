package com.gskart.user.controllers;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.DTOs.UserDto;
import com.gskart.user.DTOs.requests.TokenRequest;
import com.gskart.user.DTOs.response.ClaimsResponse;
import com.gskart.user.DTOs.response.IntrospectionResponse;
import com.gskart.user.DTOs.response.TokenResponse;
import com.gskart.user.DTOs.results.LoginResult;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.exceptions.RefreshTokenException;
import com.gskart.user.exceptions.UserException;
import com.gskart.user.exceptions.UserNotExistsException;
import com.gskart.user.mappers.Mapper;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.services.IAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

/**
 * OAuth2/OIDC-aligned endpoints for issuing, refreshing, revoking, and introspecting tokens.
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Auth", description = "OAuth2/OIDC token issuance, revocation, introspection, and userinfo")
public class AuthController {

    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    private final IAuthService authService;
    private final Mapper mapper;
    private final long accessTokenExpiryMinutes;

    public AuthController(IAuthService authService, Mapper mapper,
                           @Value("${gskart.jwt.access-token.expiry-minutes}") long accessTokenExpiryMinutes) {
        this.authService = authService;
        this.mapper = mapper;
        this.accessTokenExpiryMinutes = accessTokenExpiryMinutes;
    }

    /**
     * Issues an access + refresh token pair (RFC 6749): grantType=password exchanges
     * credentials; grantType=refresh_token rotates a valid refresh token.
     */
    @Operation(summary = "Issue a token", description = "grantType=password exchanges credentials; grantType=refresh_token rotates a refresh token")
    @PostMapping("/oauth2/token")
    public ResponseEntity<TokenResponse> token(@Valid @RequestBody TokenRequest tokenRequest)
            throws UserException, UserNotExistsException, RefreshTokenException, JwtKeyStoreException {
        LoginResult loginResult = switch (tokenRequest.getGrantType()) {
            case GRANT_TYPE_PASSWORD -> {
                if (!StringUtils.hasText(tokenRequest.getUsername()) || !StringUtils.hasText(tokenRequest.getPassword())) {
                    throw new UserException("username and password are required for grantType=password");
                }
                yield authService.login(tokenRequest.getUsername(), tokenRequest.getPassword());
            }
            case GRANT_TYPE_REFRESH_TOKEN -> {
                if (!StringUtils.hasText(tokenRequest.getRefreshToken())) {
                    throw new UserException("refreshToken is required for grantType=refresh_token");
                }
                yield authService.refresh(tokenRequest.getRefreshToken());
            }
            default -> throw new UserException("Unsupported grantType: " + tokenRequest.getGrantType());
        };

        if (loginResult == null || loginResult.getUser() == null) {
            throw new UserNotExistsException("Invalid username or password");
        }

        return ResponseEntity.ok(buildTokenResponse(loginResult));
    }

    /**
     * Revokes the caller's access token (RFC 7009): blacklists it and revokes their refresh tokens.
     */
    @Operation(summary = "Revoke the caller's token")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/oauth2/revoke")
    public ResponseEntity<Void> revoke(@RequestHeader(value = "Authorization", required = false) String authHeader)
            throws JwtKeyStoreException, JwtNotValidException {
        authService.logout(extractCallerBearerToken(authHeader));
        return ResponseEntity.noContent().build();
    }

    /**
     * Introspects a token's claimed identity against the authenticated caller (RFC 7662).
     */
    @Operation(summary = "Introspect a token's claimed identity against the authenticated caller")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/oauth2/introspect")
    public ResponseEntity<IntrospectionResponse> introspect(@Valid @RequestBody UserDto userDto) {
        UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Set<RoleDto> requestedRoles = userDto.getRoles() != null ? userDto.getRoles() : Set.of();

        boolean active = principal.getUsername().equals(userDto.getUsername())
                && principal.getAuthorities().stream().anyMatch(authority ->
                        requestedRoles.stream().anyMatch(role -> authority.getAuthority().equals(role.getName())));

        IntrospectionResponse response = new IntrospectionResponse();
        response.setActive(active);
        response.setUsername(principal.getUsername());
        return ResponseEntity.ok(response);
    }

    /**
     * OIDC UserInfo — returns claims for the authenticated caller, consumed by resource servers.
     */
    @Operation(summary = "Return claims for the authenticated caller (OIDC UserInfo)")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/userinfo")
    public ResponseEntity<ClaimsResponse> userInfo() {
        GSKartUserDetails userDetails = (GSKartUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ClaimsResponse response = mapper.userEntityToClaimsResponse(userDetails.getUserEntity());
        return ResponseEntity.ok(response);
    }

    private TokenResponse buildTokenResponse(LoginResult loginResult) {
        // AuthService.buildLoginResult always sets a well-formed "Bearer <token>" header itself
        // (not client-supplied input), so this substring is safe without re-validating the format.
        String authHeader = loginResult.getAuthenticationHeader().getFirst(HttpHeaders.AUTHORIZATION);
        TokenResponse response = new TokenResponse();
        response.setAccessToken(authHeader.substring(7));
        response.setTokenType("Bearer");
        response.setExpiresIn(accessTokenExpiryMinutes * 60);
        response.setRefreshToken(loginResult.getRefreshToken());
        return response;
    }

    private String extractCallerBearerToken(String authHeader) throws JwtNotValidException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new JwtNotValidException("Missing or malformed Authorization header", new IllegalArgumentException());
        }
        return authHeader.substring(7);
    }

    // TODO forget password (FR-U5, depends on notifications-service)
}
