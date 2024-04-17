package com.gskart.user.security.filters;

import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import com.gskart.user.security.services.GSKartUserService;
import com.gskart.user.utils.JwtHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    private final JwtHelper jwtHelper;
    private final GSKartUserService gsKartUserService;

    public JwtAuthFilter(JwtHelper jwtHelper, GSKartUserService gsKartUserService) {
        this.jwtHelper = jwtHelper;
        this.gsKartUserService = gsKartUserService;
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
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            // log the exception
            return;
        } catch (JwtNotValidException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // log the exception
            return;
        }
        filterChain.doFilter(request, response);
    }
}
