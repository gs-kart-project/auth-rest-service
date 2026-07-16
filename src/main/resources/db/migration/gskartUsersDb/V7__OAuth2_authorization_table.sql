-- Backing store for JdbcOAuth2AuthorizationService: one row per issued authorization, so refresh
-- tokens survive a restart and stay revocable.
--
-- Adapted from the canonical Spring Authorization Server schema
-- (oauth2-authorization-schema.sql) with two deliberate changes for MySQL:
--   * timestamp -> datetime(6), which matches the rest of this schema and sidesteps the MySQL
--     timestamp range limit (1970-2038) on refresh-token expiry.
--   * engine=InnoDB, per the house convention in the earlier migrations.
-- Registered clients are in-memory and consent is disabled, so the companion oauth2_registered_client
-- and oauth2_authorization_consent tables are intentionally not created.
create table oauth2_authorization (
    id varchar(100) not null,
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    authorization_grant_type varchar(100) not null,
    authorized_scopes varchar(1000) default null,
    attributes blob default null,
    state varchar(500) default null,
    authorization_code_value blob default null,
    authorization_code_issued_at datetime(6) default null,
    authorization_code_expires_at datetime(6) default null,
    authorization_code_metadata blob default null,
    access_token_value blob default null,
    access_token_issued_at datetime(6) default null,
    access_token_expires_at datetime(6) default null,
    access_token_metadata blob default null,
    access_token_type varchar(100) default null,
    access_token_scopes varchar(1000) default null,
    oidc_id_token_value blob default null,
    oidc_id_token_issued_at datetime(6) default null,
    oidc_id_token_expires_at datetime(6) default null,
    oidc_id_token_metadata blob default null,
    refresh_token_value blob default null,
    refresh_token_issued_at datetime(6) default null,
    refresh_token_expires_at datetime(6) default null,
    refresh_token_metadata blob default null,
    user_code_value blob default null,
    user_code_issued_at datetime(6) default null,
    user_code_expires_at datetime(6) default null,
    user_code_metadata blob default null,
    device_code_value blob default null,
    device_code_issued_at datetime(6) default null,
    device_code_expires_at datetime(6) default null,
    device_code_metadata blob default null,
    primary key (id)
) engine=InnoDB;

create index IDX_OAuth2Authorization_PrincipalName on oauth2_authorization (principal_name);
