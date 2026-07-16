package com.gskart.user.security.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.gskart.user.entities.User;

/**
 * Serializes GSKartUserDetails as its wrapped user only, ignoring the UserDetails getters
 * (authorities, password, the status flags) which are all derived from it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class GskartUserDetailsMixin {

    @JsonCreator
    GskartUserDetailsMixin(@JsonProperty("user") User user) {
    }
}
