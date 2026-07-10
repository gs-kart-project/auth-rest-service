use gskartUsers;

-- Bootstraps a Developer role and an initial admin user so the Developer-gated
-- User/Role CRUD endpoints (UserController/RoleController) are reachable without
-- manual DB surgery. Username/email/password-hash come from Flyway placeholders
-- (application.properties -> env vars), not literals, so no credential is committed.
-- Every insert is NOT EXISTS-guarded so re-baselining is a no-op.
-- Placeholders are raw string-interpolated by Flyway (not bind params) — fine since
-- adminUsername/adminEmail are operator-controlled, but neither may contain a single quote or
-- it will break this migration.

insert into roles (name, description, created_by, created_on)
select 'Developer', 'Bootstrap admin/developer role', 'system', utc_timestamp(6)
where not exists (select 1 from roles where name = 'Developer');

-- user_status = 1 -> ACTIVE, credentials_status = 1 -> ACTIVE (ordinals of
-- com.gskart.user.entities.User.UserStatus / CredentialsStatus, 0-indexed by declaration order).
insert into users (username, email, password, firstname, lastname, user_status, credentials_status, created_by, created_on)
select '${adminUsername}', '${adminEmail}', '${adminPasswordHash}', 'Admin', 'Bootstrap', 1, 1, 'system', utc_timestamp(6)
where not exists (select 1 from users where username = '${adminUsername}');

insert into users_roles (users_id, roles_id)
select u.id, r.id
from users u, roles r
where u.username = '${adminUsername}' and r.name = 'Developer'
  and not exists (
    select 1 from users_roles ur where ur.users_id = u.id and ur.roles_id = r.id
  );
