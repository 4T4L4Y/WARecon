#!/bin/bash
set -euo pipefail

mkdir -p "${DATA_DIR}/outputs" "${DATA_DIR}/staticfiles"

echo "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."
until python - <<'PY'
import os, sys
import redis
host = os.environ.get("REDIS_HOST", "redis")
port = int(os.environ.get("REDIS_PORT", "6379"))
db = int(os.environ.get("REDIS_DB", "0"))
redis.Redis(host=host, port=port, db=db, socket_connect_timeout=2).ping()
PY
do
  sleep 1
done
echo "Redis is up."

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec "$@"
