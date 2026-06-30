# Auth Service
Auth service handles the following functionalities
1. User management
2. Authentication and Authorization
3. Session management
## User Management
TBU

## Local database

A single shared MySQL container ("gskart-mysql") is used for local dev. It's grouped under the
"gskart" project in OrbStack/Docker, and hosts one database per GS Kart service (currently just
`gskartUsers` for auth).

1. Copy `.env.example` to `.env` and fill in real values (never commit `.env`):
   ```
   cp .env.example .env
   ```
2. Start the container:
   ```
   docker compose up -d
   ```
   First boot runs `docker/mysql/init/01-init-databases.sh`, which creates the `gskartUsers`
   database and the app user/grants. This script is idempotent — re-run it any time (e.g. after
   adding a new service schema to it) against a live container:
   ```
   docker exec gskart-mysql sh /docker-entrypoint-initdb.d/01-init-databases.sh
   ```
3. Run the app with the same env vars loaded (the app runs on the host, not in Compose):
   ```
   set -a; source .env; set +a
   ./mvnw spring-boot:run
   ```
   Flyway then applies the migrations under `src/main/resources/db/migration/gskartUsersDb`.

To add another service's schema later, append `CREATE DATABASE IF NOT EXISTS ...` /
`GRANT ALL PRIVILEGES ...` statements to `docker/mysql/init/01-init-databases.sh` and re-run it
against the live container.
