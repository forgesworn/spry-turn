#!/bin/sh
set -eu

if [ -z "${SPRY_TURN_SECRET:-}" ] && [ -f /run/secrets/spry_turn_secret ]; then
    SPRY_TURN_SECRET="$(cat /run/secrets/spry_turn_secret)"
    export SPRY_TURN_SECRET
fi

exec "$@"
