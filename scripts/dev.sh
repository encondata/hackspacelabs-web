#!/bin/sh
# Local development server: SQLite by default (no Postgres needed), auto-reload, migrations applied.
# Uses settings from .env when present; KILN_DATABASE_URL there overrides the SQLite default.
set -e
cd "$(dirname "$0")/.."
mkdir -p data
export KILN_ENV="${KILN_ENV:-development}"
if ! grep -qs '^KILN_DATABASE_URL=' .env; then
  export KILN_DATABASE_URL="${KILN_DATABASE_URL:-sqlite+aiosqlite:///$(pwd)/data/kiln-dev.db}"
fi
.venv/bin/kiln migrate
exec .venv/bin/kiln serve --host 127.0.0.1 --port "${PORT:-8000}" --reload
