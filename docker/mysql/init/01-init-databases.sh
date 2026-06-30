#!/bin/sh
# GS Kart — local-dev MySQL provisioning (source of truth).
# Idempotent: auto-runs on container first-boot (mounted into /docker-entrypoint-initdb.d/)
# and is safe to re-run manually against a live container:
#   docker exec gskart-mysql sh /docker-entrypoint-initdb.d/01-init-databases.sh
# Secrets are read from container env (populated from .env) — nothing secret is committed.
set -e

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE DATABASE IF NOT EXISTS gskartUsers CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${GSKART_DB_USER}'@'%' IDENTIFIED BY '${GSKART_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON gskartUsers.* TO '${GSKART_DB_USER}'@'%';
-- Add future local service schemas here (one container, many DBs), e.g.:
-- CREATE DATABASE IF NOT EXISTS gskartCart CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- GRANT ALL PRIVILEGES ON gskartCart.* TO '${GSKART_DB_USER}'@'%';
FLUSH PRIVILEGES;
SQL
