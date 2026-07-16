package com.gskart.user.security.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.gskart.user.entities.Role;

import java.util.Set;

/**
 * Keeps the persisted principal down to what minting a token needs.
 *
 * The password hash is deliberately dropped: the stored principal is only ever replayed to issue
 * new tokens on refresh, never to re-check a password, so there is no reason to copy the hash into
 * the authorization store. The audit columns are dropped because they carry OffsetDateTime values
 * that would otherwise need polymorphic type handling for no benefit.
 */
@JsonIgnoreProperties(value = {"id", "createdBy", "createdOn", "modifiedBy", "modifiedOn"},
        ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class UserMixin {

    @JsonIgnore
    private String password;

    /**
     * Roles are read off the Authentication's granted authorities instead (see
     * GskartTokenCustomizer). Serializing them from here would persist Hibernate's PersistentSet
     * implementation type into the authorization store, which cannot be read back outside a
     * session.
     */
    @JsonIgnore
    private Set<Role> roles;
}
