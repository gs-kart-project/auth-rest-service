package com.gskart.user.security.filters;

import com.gskart.user.entities.Role;
import com.gskart.user.entities.User;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.security.ProblemDetailResponseWriter;
import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.security.services.GSKartUserService;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtHelper jwtHelper;

    @Mock
    private GSKartUserService gsKartUserService;

    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Mock
    private FilterChain filterChain;

    @Mock
    private Claims claims;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private JwtAuthFilter jwtAuthFilter;

    @BeforeEach
    void setUp() {
        jwtAuthFilter = new JwtAuthFilter(jwtHelper, gsKartUserService, blacklistedTokenRepository,
                new ProblemDetailResponseWriter(objectMapper));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_noAuthorizationHeader_proceedsWithoutWritingResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
        verifyNoInteractions(jwtHelper);
    }

    @Test
    void doFilterInternal_blacklistedToken_writes401ProblemDetailAndStopsChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer sometoken");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtHelper.getClaimsFromToken("sometoken")).thenReturn(claims);
        when(claims.getId()).thenReturn("jti-123");
        when(blacklistedTokenRepository.existsByTokenId("jti-123")).thenReturn(true);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertProblemDetailResponse(response, HttpStatus.UNAUTHORIZED, "Invalid or expired authentication token.");
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_invalidToken_writes401ProblemDetailAndStopsChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer badtoken");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtHelper.getClaimsFromToken("badtoken"))
                .thenThrow(new JwtNotValidException("expired", null));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertProblemDetailResponse(response, HttpStatus.UNAUTHORIZED, "Invalid or expired authentication token.");
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_keystoreFailure_writes500ProblemDetailAndStopsChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer sometoken");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtHelper.getClaimsFromToken("sometoken"))
                .thenThrow(new JwtKeyStoreException("keystore unreadable"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertProblemDetailResponse(response, HttpStatus.INTERNAL_SERVER_ERROR,
                "Unexpected error occurred. Unable to process this request.");
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_validToken_setsAuthenticationAndProceeds() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer goodtoken");
        MockHttpServletResponse response = new MockHttpServletResponse();

        User user = new User();
        user.setUsername("jdoe");
        Role role = new Role();
        role.setName("USER");
        user.setRoles(Set.of(role));
        user.setUserStatus(User.UserStatus.ACTIVE);
        user.setCredentialsStatus(User.CredentialsStatus.ACTIVE);

        when(jwtHelper.getClaimsFromToken("goodtoken")).thenReturn(claims);
        when(claims.getId()).thenReturn("jti-456");
        when(claims.getSubject()).thenReturn("jdoe");
        when(blacklistedTokenRepository.existsByTokenId("jti-456")).thenReturn(false);
        when(gsKartUserService.loadUserByUsername("jdoe")).thenReturn(new GSKartUserDetails(user));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("jdoe");
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private void assertProblemDetailResponse(MockHttpServletResponse response, HttpStatus expectedStatus,
            String expectedDetail) throws Exception {
        assertThat(response.getStatus()).isEqualTo(expectedStatus.value());
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(new MediaType(MediaType.APPLICATION_PROBLEM_JSON, StandardCharsets.UTF_8));
        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(expectedStatus.value());
        assertThat(body.get("detail").asString()).isEqualTo(expectedDetail);
    }
}
