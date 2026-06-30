create table refresh_tokens (
                       revoked bit not null, created_on datetime(6), expires_on datetime(6), id bigint not null auto_increment, modified_on datetime(6),
                       created_by varchar(255), modified_by varchar(255), token varchar(255), username varchar(255), primary key (id)) engine=InnoDB;

create table blacklisted_tokens (
                       created_on datetime(6), expires_on datetime(6), id bigint not null auto_increment, modified_on datetime(6),
                       created_by varchar(255), modified_by varchar(255), token_id varchar(255), primary key (id)) engine=InnoDB;

create unique index UK_RefreshTokens_Token on refresh_tokens (token);

create index IDX_BlacklistedTokens_TokenId on blacklisted_tokens (token_id);
