#!/bin/sh
# Local development server: SQLite by default (no Postgres needed), auto-reload, migrations applied.
# Uses settings from .env when present; SLIPWAY_DATABASE_URL there overrides the SQLite default.
set -e
cd "$(dirname "$0")/.."
mkdir -p data
export SLIPWAY_ENV="${SLIPWAY_ENV:-development}"
if ! grep -qs '^SLIPWAY_DATABASE_URL=' .env; then
  export SLIPWAY_DATABASE_URL="${SLIPWAY_DATABASE_URL:-sqlite+aiosqlite:///$(pwd)/data/slipway-dev.db}"
fi
.venv/bin/slipway migrate
exec .venv/bin/slipway serve --host 127.0.0.1 --port "${PORT:-8000}" --reload
