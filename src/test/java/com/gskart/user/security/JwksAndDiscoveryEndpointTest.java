package com.gskart.user.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The JWKS and discovery documents are the contract product/cart depend on: they fetch the key from
 * here instead of calling back to auth on every request.
 */
@SpringBootTest
@AutoConfigureMockMvc
class JwksAndDiscoveryEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void jwksEndpointIsPublicAndPublishesTheSigningKey() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("gskart-jwt-key"));
    }

    /** The private key must never leave the server: no "d" (private exponent) in the JWKS. */
    @Test
    void jwksDoesNotExposeThePrivateKey() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }

    @Test
    void discoveryDocumentAdvertisesTheConfiguredIssuerAndEndpoints() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:4011"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:4011/oauth2/token"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:4011/oauth2/jwks"));
    }

    @Test
    void oidcDiscoveryDocumentIsAvailableForTheFuturePortal() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:4011"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost:4011/userinfo"));
    }
}
