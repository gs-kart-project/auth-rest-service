package com.gskart.user.security.filters;

import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.repositories.BlacklistedTokenRepository;
import com.gskart.user.security.ProblemDetailResponseWriter;
import com.gskart.user.security.services.GSKartUserService;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private static final String INVALID_TOKEN_DETAIL = "Invalid or expired authentication token.";

    private final JwtHelper jwtHelper;
    private final GSKartUserService gsKartUserService;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final ProblemDetailResponseWriter responseWriter;

    public JwtAuthFilter(JwtHelper jwtHelper, GSKartUserService gsKartUserService,
            BlacklistedTokenRepository blacklistedTokenRepository, ProblemDetailResponseWriter responseWriter) {
        this.jwtHelper = jwtHelper;
        this.gsKartUserService = gsKartUserService;
        this.blacklistedTokenRepository = blacklistedTokenRepository;
        this.responseWriter = responseWriter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // If token is not present, continue with the processing of other filters in the filter chain.
            filterChain.doFilter(request, response);
            return;
        }
        String token = authHeader.substring(7);

        try {
            Claims claims = jwtHelper.getClaimsFromToken(token);
            if(blacklistedTokenRepository.existsByTokenId(claims.getId())) {
                log.warn("Rejected blacklisted token for request to {}", request.getRequestURI());
                responseWriter.write(response, HttpStatus.UNAUTHORIZED, INVALID_TOKEN_DETAIL);
                return;
            }
            String username = claims.getSubject();
            if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = gsKartUserService.loadUserByUsername(username);
                if(userDetails != null) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (JwtKeyStoreException e) {
            log.error("JWT keystore error while authenticating request to {}", request.getRequestURI(), e);
            responseWriter.write(response, HttpStatus.INTERNAL_SERVER_ERROR,
                    "Unexpected error occurred. Unable to process this request.");
            return;
        } catch (JwtNotValidException e) {
            log.warn("Invalid token on request to {}: {}", request.getRequestURI(), e.getMessage());
            responseWriter.write(response, HttpStatus.UNAUTHORIZED, INVALID_TOKEN_DETAIL);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
