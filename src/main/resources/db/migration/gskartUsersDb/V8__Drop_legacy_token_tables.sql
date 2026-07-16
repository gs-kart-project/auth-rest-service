-- The hand-rolled token store is gone: refresh tokens now live in oauth2_authorization (V7) and
-- access tokens are short-lived and non-revocable, so the blacklist has nothing to hold.
drop table if exists refresh_tokens;
drop table if exists blacklisted_tokens;
