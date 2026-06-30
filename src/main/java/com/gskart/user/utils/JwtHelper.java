package com.gskart.user.utils;

import com.gskart.user.DTOs.RoleDto;
import com.gskart.user.entities.Role;
import com.gskart.user.exceptions.JwtKeyStoreException;
import com.gskart.user.exceptions.JwtNotValidException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.InvalidKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@Component
public class JwtHelper {
    private static final Logger log = LoggerFactory.getLogger(JwtHelper.class);

    private final IGskartKeystore gskartKeystore;

    @Value("${gskart.jwt.access-token.expiry-minutes}")
    private long accessTokenExpiryMinutes;

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    public JwtHelper(IGskartKeystore gskartKeystore) {
        this.gskartKeystore = gskartKeystore;
    }

    public String generateToken(String username, String email, Set<RoleDto> roleDtoSet) throws JwtKeyStoreException {
        Instant now = Instant.now();
        String jwt = null;
        try {
            jwt = Jwts.builder()
                    .claim("email", email)
                    .claim("roles", roleDtoSet)
                    .subject(username)
                    .id(UUID.randomUUID().toString())
                    .issuer(issuer)
                    .audience().add(issuer).and()
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plus(accessTokenExpiryMinutes, ChronoUnit.MINUTES)))
                    .signWith(gskartKeystore.readPrivateKey())
                    .compact();
        } catch (CertificateException e) {
            throw new JwtKeyStoreException("Unable to generate Token due to CertificateException while reading private key.", e);
        } catch (KeyStoreException e) {
            throw new JwtKeyStoreException("Unable to generate Token due to KeyStoreException while reading private key.", e);
        } catch (IOException e) {
            throw new JwtKeyStoreException("Unable to generate Token due to IOException while reading private key.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new JwtKeyStoreException("Unable to generate Token due to NoSuchAlgorithmException while reading private key.", e);
        } catch (UnrecoverableKeyException e) {
            throw new JwtKeyStoreException("Unable to generate Token due to UnrecoverableKeyException while reading private key.", e);
        }

        return jwt;
    }

    public Claims getClaimsFromToken(String token) throws JwtKeyStoreException, JwtNotValidException {
        JwtParser parser = null;
        Claims claims = null;
        try {
            parser = Jwts.parser()
                    .verifyWith(gskartKeystore.readPublicKey())
                    .requireIssuer(issuer)
                    .build();
            claims = parser.parseSignedClaims(token).getPayload();
        } catch (CertificateException e) {
            throw new JwtKeyStoreException("Unable to get claims from Token due to CertificateException while reading public key.", e);
        } catch (KeyStoreException e) {
            throw new JwtKeyStoreException("Unable to get claims from Token due to KeyStoreException while reading public key.", e);
        } catch (IOException e) {
            throw new JwtKeyStoreException("Unable to get claims from Token due to IOException while reading public key.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new JwtKeyStoreException("Unable to get claims from Token due to NoSuchAlgorithmException while reading public key.", e);
        }
        catch (ExpiredJwtException e) {
            log.warn("Unable to get claims from Token as the JWT provided is expired", e);
            throw new JwtNotValidException("Unable to get claims from Token as the JWT provided is expired", e);
        }
        catch (UnsupportedJwtException | InvalidKeyException e) {
            log.warn("Unable to get claims from Token as the JWT provided is not issued by Auth server", e);
            throw new JwtNotValidException("Unable to get claims from Token as the JWT provided is not issued by Auth server.", e);
        }
        catch (MalformedJwtException e){
            log.warn("Unable to get claims from Token as the JWT provided is invalid or Malformed", e);
            throw new JwtNotValidException("Unable to get claims from Token as the JWT provided is invalid or Malformed.", e);
        }
        catch (IncorrectClaimException e){
            log.warn("Unable to get claims from Token as the JWT provided has an unexpected issuer", e);
            throw new JwtNotValidException("Unable to get claims from Token as the JWT provided has an unexpected issuer.", e);
        }
        return claims;
    }


}
