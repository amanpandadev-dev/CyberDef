# Production PostgreSQL Setup Guide

## Prerequisites

```bash
# Install PostgreSQL (macOS)
brew install postgresql@15
brew services start postgresql@15

# Or using Docker (recommended for consistency)
docker run --name aegisnet-postgres \
  -e POSTGRES_USER=aegisnet \
  -e POSTGRES_PASSWORD=your_secure_password \
  -e POSTGRES_DB=aegisnet \
  -p 5432:5432 \
  -v aegisnet_data:/var/lib/postgresql/data \
  -d postgres:15-alpine
```

## Install Python Driver

```bash
pip install asyncpg  # High-performance async PostgreSQL driver
```

## Configuration

Update your `.env` file:

```bash
# Development (SQLite)
DATABASE_URL=sqlite+aiosqlite:///./data/aegisnet.db

# Production (PostgreSQL)
DATABASE_URL=postgresql+asyncpg://aegisnet:your_secure_password@localhost:5432/aegisnet
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
DB_ECHO=false
```

## Performance Tuning

For 45MB files every 15 minutes, recommended PostgreSQL config (`postgresql.conf`):

```ini
# Connection Settings
max_connections = 100

# Memory Settings (for 8GB RAM server)
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 32MB
maintenance_work_mem = 512MB

# Write Performance
wal_buffers = 16MB
checkpoint_completion_target = 0.9
max_wal_size = 4GB

# Parallel Query
max_parallel_workers_per_gather = 4
max_worker_processes = 8
```

## Create Database & User

```sql
CREATE USER aegisnet WITH PASSWORD 'your_secure_password';
CREATE DATABASE aegisnet OWNER aegisnet;
GRANT ALL PRIVILEGES ON DATABASE aegisnet TO aegisnet;
```

## Verify Connection

```bash
# Test connection
psql -U aegisnet -d aegisnet -h localhost

# Within Python
python -c "from database import init_db; import asyncio; asyncio.run(init_db())"
```

## Migration from SQLite

```bash
# Backup SQLite data
cp data/aegisnet.db data/aegisnet.db.backup

# Export to CSV (if needed)
sqlite3 data/aegisnet.db ".mode csv" ".output files.csv" "SELECT * FROM files;"

# Switch to PostgreSQL in .env
# Run server - schema will auto-create
python main.py
```

## Monitoring

```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'aegisnet';

-- Table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Slow queries
SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;
```
