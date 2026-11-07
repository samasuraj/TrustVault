#!/bin/sh
set -e

echo "Waiting for database..."
python -c "
import time, os, psycopg2
url = os.getenv('DATABASE_URL', 'postgresql+psycopg2://vault:vaultpass@db:5432/trustvault')
dsn = url.replace('postgresql+psycopg2://', 'postgresql://')
for i in range(30):
    try:
        conn = psycopg2.connect(dsn)
        conn.close()
        break
    except Exception as e:
        time.sleep(1)
else:
    raise SystemExit('Database not ready')
"

echo "Running migrations..."
alembic upgrade head

echo "Seeding initial users if needed..."
python -m app.seed

echo "Starting server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
