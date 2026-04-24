#!/bin/sh
set -e

# In ECS, individual DB vars are injected from Secrets Manager.
# In docker-compose, DATABASE_URL is set directly.
if [ -z "$DATABASE_URL" ] && [ -n "$DB_HOST" ]; then
  export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"
fi

if [ -n "$DATABASE_URL" ]; then
  DB_CONNECT_HOST=$(node -e "try{const u=new URL(process.env.DATABASE_URL);console.log(u.hostname)}catch(e){console.log('localhost')}")
  DB_CONNECT_PORT=$(node -e "try{const u=new URL(process.env.DATABASE_URL);console.log(u.port||'5432')}catch(e){console.log('5432')}")
  DB_CONNECT_USER=$(node -e "try{const u=new URL(process.env.DATABASE_URL);console.log(u.username)}catch(e){console.log('postgres')}")

  echo "Waiting for PostgreSQL at $DB_CONNECT_HOST:$DB_CONNECT_PORT..."
  RETRIES=30
  until pg_isready -h "$DB_CONNECT_HOST" -p "$DB_CONNECT_PORT" -U "$DB_CONNECT_USER" 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -eq 0 ]; then
      echo "Warning: PostgreSQL not ready after 60s, starting anyway"
      break
    fi
    sleep 2
  done
fi

echo "Initializing database schema..."
node init_db.js || echo "Warning: DB init returned non-zero (schema may already exist)"

echo "Starting Vanquish server..."
exec node index.js
