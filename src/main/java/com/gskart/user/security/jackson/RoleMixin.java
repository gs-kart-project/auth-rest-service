package com.gskart.user.security.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Only the role name and description matter to a token; the audit columns don't. */
@JsonIgnoreProperties(value = {"id", "createdBy", "createdOn", "modifiedBy", "modifiedOn"},
        ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class RoleMixin {
}
