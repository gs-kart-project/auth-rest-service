-- The H2 test database is shared across contexts (DB_CLOSE_DELAY=-1), so the schema script runs
-- once per context. Drop first to keep it re-runnable; Hibernate's create-drop does the same for
-- the JPA-managed tables.
drop table if exists oauth2_authorization;
