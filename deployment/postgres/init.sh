#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\getenv identity_password KEYCLOAK_DB_PASSWORD
\getenv app_password APP_DB_PASSWORD
SELECT format('CREATE ROLE hsl_identity LOGIN PASSWORD %L', :'identity_password') \gexec
SELECT format('CREATE ROLE hsl_web LOGIN PASSWORD %L', :'app_password') \gexec
CREATE DATABASE hsl_identity OWNER hsl_identity;
CREATE DATABASE hsl_sessions OWNER hsl_web;
REVOKE ALL ON DATABASE hsl_identity FROM PUBLIC;
REVOKE ALL ON DATABASE hsl_sessions FROM PUBLIC;
GRANT CONNECT ON DATABASE hsl_identity TO hsl_identity;
GRANT CONNECT ON DATABASE hsl_sessions TO hsl_web;
\connect hsl_sessions
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE public.web_sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamp(6) NOT NULL
);
CREATE INDEX web_sessions_expire_idx ON public.web_sessions(expire);
ALTER TABLE public.web_sessions OWNER TO hsl_web;
SQL
