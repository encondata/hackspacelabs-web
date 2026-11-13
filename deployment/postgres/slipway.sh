#!/bin/sh
# Idempotently provision Slipway's database role and database.
# Runs as an init script on an empty volume, and again on every install/update (setup.sh executes it in the
# running postgres container), so existing installations gain the database without resetting anything.
# The role password is re-applied each run so it always matches SLIPWAY_DB_PASSWORD in deployment/.env.
set -eu
: "${SLIPWAY_DB_PASSWORD:?SLIPWAY_DB_PASSWORD is required}"
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\getenv slipway_password SLIPWAY_DB_PASSWORD
SELECT 'CREATE ROLE hsl_slipway LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'hsl_slipway') \gexec
SELECT format('ALTER ROLE hsl_slipway WITH LOGIN PASSWORD %L', :'slipway_password') \gexec
SELECT 'CREATE DATABASE hsl_slipway OWNER hsl_slipway' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'hsl_slipway') \gexec
REVOKE ALL ON DATABASE hsl_slipway FROM PUBLIC;
GRANT CONNECT ON DATABASE hsl_slipway TO hsl_slipway;
\connect hsl_slipway
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
