#!/bin/sh
# Apply database migrations, then run the given command (default: kiln serve).
set -e
if [ "${KILN_SKIP_MIGRATIONS:-0}" != "1" ]; then
  kiln migrate
fi
exec "$@"
