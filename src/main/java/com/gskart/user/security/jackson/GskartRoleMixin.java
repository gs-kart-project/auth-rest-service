package com.gskart.user.security.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.gskart.user.entities.Role;

/** GSKartRole is a thin GrantedAuthority over a Role; persist the role, not the derived authority. */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class GskartRoleMixin {

    @JsonCreator
    GskartRoleMixin(@JsonProperty("role") Role role) {
    }
}
