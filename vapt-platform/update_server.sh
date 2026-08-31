#!/bin/bash
set -e

echo "====================================================="
echo "   ?? VAPT Platform - Server Update Script"
echo "====================================================="

# 1. Pull latest code from GitHub
echo "[1/4] Pulling latest main branch from GitHub..."
git pull origin main

# 2. Identify docker compose command
DOCKER_COMPOSE_CMD="docker compose"
if ! docker compose version &> /dev/null; then
    if which docker-compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker-compose"
    else
        echo "? Error: Docker Compose is not installed."
        exit 1
    fi
fi

# 3. Build and recreate API and Frontend containers
echo "[2/4] Rebuilding and updating API & Frontend containers..."
$DOCKER_COMPOSE_CMD up -d --build --force-recreate api frontend

# 4. Ensure extended profile scanning engines (ZAP, MobSF, etc.) are running
echo "[3/4] Ensuring extended scanning services are running..."
$DOCKER_COMPOSE_CMD --profile extended up -d

# 5. Verify database schema
echo "[4/4] Synchronizing database tables and models..."
API_CONTAINER=$($DOCKER_COMPOSE_CMD ps -q api)
if [ -n "$API_CONTAINER" ]; then
    docker exec "$API_CONTAINER" python3 -c "
from app.database import engine, Base
import app.models
Base.metadata.create_all(bind=engine)
print('Database schema synchronized successfully.')
"
fi

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo "====================================================="
echo "   ? VAPT Platform successfully updated!"
echo "   ?? Web Console: http://${SERVER_IP}:18080"
echo "====================================================="