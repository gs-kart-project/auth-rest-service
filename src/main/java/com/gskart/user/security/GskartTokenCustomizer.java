package com.gskart.user.security;

import com.gskart.user.security.models.GSKartUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Adds the claims resource servers rely on: the user's email and a flat list of role names
 * ("roles":["Developer","Admin"]), which product/cart map straight onto granted authorities.
 */
@Component
public class GskartTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        Authentication principal = context.getPrincipal();
        if (!(principal.getPrincipal() instanceof GSKartUserDetails userDetails)) {
            // Client-only grants carry no user; leave the token with its standard claims.
            return;
        }

        // Read from the Authentication rather than the user entity: on a refresh the principal has
        // been rehydrated from the authorization store, where the entity's role collection is not
        // persisted (see UserMixin).
        //
        // An ArrayList rather than Stream.toList(): these claims are persisted as access-token
        // metadata, and Spring Security's JSON type allowlist covers ArrayList but not the
        // List.of-style immutable types.
        List<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toCollection(ArrayList::new));

        context.getClaims()
                .claim("email", userDetails.getUserEntity().getEmail())
                .claim("roles", roles);
    }
}
