#!/bin/sh
# API container entrypoint: sync the DB schema (idempotent) then start the server.
# Kept as a script so multi-step startup doesn't rely on shell quoting in the
# platform's run command. See render.yaml / docker-compose.yml.
set -e

if [ -n "$DATABASE_URL" ]; then
  echo "Applying database schema (prisma db push)…"
  n=0
  until npx prisma db push --skip-generate; do
    n=$((n + 1))
    if [ "$n" -ge 5 ]; then
      echo "prisma db push failed after $n attempts — is DATABASE_URL reachable?"
      exit 1
    fi
    echo "Database not ready; retry $n/5 in 5s…"
    sleep 5
  done
fi

exec node dist/server.js
