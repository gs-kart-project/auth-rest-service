use gskartUsers;

-- Repoint any users_roles mappings from a duplicate-named role onto the lowest-id role sharing
-- that name, then drop the now-redundant role rows, before enforcing uniqueness on roles.name.
drop temporary table if exists tmp_role_canonical;
create temporary table tmp_role_canonical as
    select r.id as role_id, (
        select min(r2.id) from roles r2 where r2.name = r.name
    ) as canonical_id
    from roles r;

-- Snapshot (user, canonical role) pairs that already exist, before any mutation — materialized
-- so the later DELETE doesn't have to subquery the same table it's deleting from.
drop temporary table if exists tmp_existing_canonical_assignment;
create temporary table tmp_existing_canonical_assignment as
    select ur.users_id, trc.canonical_id
    from users_roles ur
    join tmp_role_canonical trc on ur.roles_id = trc.canonical_id;

-- Drop duplicate-role mappings that would collide with one the user already has via the
-- canonical role
delete ur from users_roles ur
    join tmp_role_canonical trc on ur.roles_id = trc.role_id
    join tmp_existing_canonical_assignment tex
        on tex.users_id = ur.users_id and tex.canonical_id = trc.canonical_id
    where trc.role_id <> trc.canonical_id;

-- Repoint remaining mappings from duplicate role ids onto the canonical role id
update users_roles ur
    join tmp_role_canonical trc on ur.roles_id = trc.role_id
    set ur.roles_id = trc.canonical_id
    where trc.role_id <> trc.canonical_id;

-- The duplicate role rows are now unreferenced; remove them
delete r from roles r
    join tmp_role_canonical trc on r.id = trc.role_id
    where trc.role_id <> trc.canonical_id;

drop temporary table tmp_existing_canonical_assignment;
drop temporary table tmp_role_canonical;

alter table roles add constraint UK_Roles_Name unique (name);
