#!/bin/sh
# Apply database migrations, then run the given command (default: slipway serve).
set -e
if [ "${SLIPWAY_SKIP_MIGRATIONS:-0}" != "1" ]; then
  slipway migrate
fi
exec "$@"
