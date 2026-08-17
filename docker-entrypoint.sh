#!/bin/sh
set -e

# Apply schema migrations before the app or worker starts. Idempotent, so it is
# safe for both compose services to run it — racing containers just no-op after
# the first one finishes. A deployed image is useless with an empty or stale
# database, and a VPS deploy should not require a manual `npm run db:migrate`
# (which also needs a shadow DB and is interactive by design).
if [ -n "$DATABASE_URL" ]; then
  echo "pulse: applying database migrations..."
  npx prisma migrate deploy
fi

exec "$@"