# Cyberdef 1.0 - Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Development Setup](#development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Azure Deployment](#azure-deployment)
6. [Configuration Reference](#configuration-reference)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software
| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.11+ | Backend runtime |
| Node.js | 18+ | Frontend build |
| Ollama | Latest | AI model serving |
| PostgreSQL | 15+ (prod) | Database |

### Hardware Requirements
| Environment | CPU | RAM | Storage |
|-------------|-----|-----|---------|
| Development | 4 cores | 16GB | 50GB |
| Production | 8+ cores | 32GB+ | 200GB+ SSD |

> **Note**: GPU is optional but significantly speeds up AI analysis.

---

## Development Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd CybershieldPoC_PredictiveAI
```

### 2. Install Ollama
```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve
```

### 3. Download AI Model
```bash
# Download Llama 3.1 (8B model, ~4.7GB)
ollama pull llama3.1

# Verify model
ollama list
```

### 4. Setup Python Environment
```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Configure Environment
```bash
# Copy example config
cp .env.example .env

# Edit configuration (minimal for development)
cat > .env << EOF
DEBUG=True
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1
DATABASE_URL=sqlite+aiosqlite:///./data/cyberdef.db
EOF
```

### 6. Start Backend
```bash
# Run development server
python main.py

# Or with uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 7. Setup Frontend
```bash
cd ui

# Install dependencies
npm install

# Start development server
npm run dev
```

### 8. Verify Installation
```bash
# Check health endpoint
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","version":"1.0.0","ollama":{"available":true,...}}
```

**Access Points:**
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Frontend: http://localhost:5173

---

## Production Deployment

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.11 python3.11-venv postgresql nginx

# Create application user
sudo useradd -m -s /bin/bash cyberdef
sudo su - cyberdef
```

### 2. PostgreSQL Setup

```bash
# Create database
sudo -u postgres psql << EOF
CREATE USER cyberdef WITH PASSWORD 'your-secure-password';
CREATE DATABASE cyberdef_prod OWNER cyberdef;
GRANT ALL PRIVILEGES ON DATABASE cyberdef_prod TO cyberdef;
EOF
```

### 3. Application Setup

```bash
# Clone and setup
git clone <repository-url> /opt/cyberdef
cd /opt/cyberdef

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements-prod.txt
```

### 4. Production Configuration

```bash
# Create production .env
cat > .env << EOF
DEBUG=False
API_HOST=0.0.0.0
API_PORT=8000

# Database
DATABASE_URL=postgresql+asyncpg://cyberdef:your-secure-password@localhost:5432/cyberdef_prod

# Ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1

# Storage
RAW_STORAGE_DIR=/var/lib/cyberdef/raw
PROCESSED_DIR=/var/lib/cyberdef/processed

# Security
SECRET_KEY=your-256-bit-secret-key
ALLOWED_ORIGINS=https://your-domain.com
EOF

# Create storage directories
sudo mkdir -p /var/lib/cyberdef/{raw,processed}
sudo chown -R cyberdef:cyberdef /var/lib/cyberdef
```

### 5. Systemd Services

**Backend Service:**
```bash
sudo cat > /etc/systemd/system/cyberdef-api.service << EOF
[Unit]
Description=Cyberdef API Server
After=network.target postgresql.service

[Service]
Type=simple
User=cyberdef
WorkingDirectory=/opt/cyberdef
Environment=PATH=/opt/cyberdef/venv/bin
ExecStart=/opt/cyberdef/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cyberdef-api
sudo systemctl start cyberdef-api
```

**Ollama Service:**
```bash
sudo cat > /etc/systemd/system/ollama.service << EOF
[Unit]
Description=Ollama AI Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable ollama
sudo systemctl start ollama
```

### 6. Frontend Build

```bash
cd /opt/cyberdef/ui

# Install dependencies
npm ci

# Build for production
npm run build

# Output in dist/ directory
```

### 7. Nginx Configuration

```nginx
# /etc/nginx/sites-available/cyberdef
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL certificates (use certbot for Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Frontend
    location / {
        root /opt/cyberdef/ui/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts for large file analysis
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    # Health check
    location /health {
        proxy_pass http://127.0.0.1:8000;
    }
    
    # File upload size limit
    client_max_body_size 500M;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cyberdef /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 8. SSL Certificate

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com
```

---

## Docker Deployment

### docker-compose.yml

```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: cyberdef
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: cyberdef
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cyberdef"]
      interval: 5s
      timeout: 5s
      retries: 5

  ollama:
    image: ollama/ollama:latest
    volumes:
      - ollama_data:/root/.ollama
    ports:
      - "11434:11434"
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

  api:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=postgresql+asyncpg://cyberdef:${DB_PASSWORD}@db:5432/cyberdef
      - OLLAMA_HOST=http://ollama:11434
      - OLLAMA_MODEL=llama3.1
    depends_on:
      db:
        condition: service_healthy
      ollama:
        condition: service_started
    volumes:
      - ./data:/app/data
    ports:
      - "8000:8000"

  frontend:
    build:
      context: ./ui
      dockerfile: Dockerfile
    ports:
      - "80:80"
    depends_on:
      - api

volumes:
  postgres_data:
  ollama_data:
```

### Backend Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-prod.txt .
RUN pip install --no-cache-dir -r requirements-prod.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p data/raw data/processed

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Frontend Dockerfile

```dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### Run with Docker

```bash
# Set database password
export DB_PASSWORD=your-secure-password

# Pull Ollama model first
docker exec -it cyberdef-ollama-1 ollama pull llama3.1

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api
```

---

## Azure Deployment

### Architecture
```
Azure Container Apps (API)
    ↓
Azure Database for PostgreSQL
Azure Blob Storage (file storage)
Azure Container Apps (Ollama) or Azure OpenAI
```

### 1. Create Resources

```bash
# Variables
RESOURCE_GROUP=cyberdef-rg
LOCATION=eastus
ACR_NAME=cyberdefacr

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create container registry
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic

# Create PostgreSQL
az postgres flexible-server create \
  --resource-group $RESOURCE_GROUP \
  --name cyberdef-db \
  --admin-user cyberdef \
  --admin-password $DB_PASSWORD \
  --sku-name Standard_B1ms \
  --tier Burstable
```

### 2. Build and Push Images

```bash
# Login to ACR
az acr login --name $ACR_NAME

# Build and push API
docker build -t $ACR_NAME.azurecr.io/cyberdef-api:latest .
docker push $ACR_NAME.azurecr.io/cyberdef-api:latest

# Build and push Frontend
cd ui
docker build -t $ACR_NAME.azurecr.io/cyberdef-web:latest .
docker push $ACR_NAME.azurecr.io/cyberdef-web:latest
```

### 3. Deploy Container Apps

```bash
# Create Container Apps environment
az containerapp env create \
  --name cyberdef-env \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Deploy API
az containerapp create \
  --name cyberdef-api \
  --resource-group $RESOURCE_GROUP \
  --environment cyberdef-env \
  --image $ACR_NAME.azurecr.io/cyberdef-api:latest \
  --target-port 8000 \
  --ingress external \
  --env-vars \
    DATABASE_URL=postgresql+asyncpg://... \
    OLLAMA_HOST=http://... \
  --min-replicas 1 \
  --max-replicas 5
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `False` | Enable debug mode |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API port |
| `DATABASE_URL` | SQLite | Database connection string |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.1` | AI model name |
| `RAW_STORAGE_DIR` | `./data/raw` | Raw file storage |
| `PROCESSED_DIR` | `./data/processed` | Processed data storage |
| `SECRET_KEY` | (required) | Application secret |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

### Performance Tuning

```bash
# .env for high-performance
UVICORN_WORKERS=8
CHUNK_BATCH_SIZE=500
AI_MAX_CONCURRENT=4
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
```

---

## Troubleshooting

### Common Issues

**1. Ollama Connection Failed**
```bash
# Check Ollama status
systemctl status ollama
curl http://localhost:11434/api/tags

# Restart if needed
systemctl restart ollama
```

**2. Database Connection Error**
```bash
# Test PostgreSQL
psql -h localhost -U cyberdef -d cyberdef_prod

# Check pg_hba.conf for local connections
sudo cat /etc/postgresql/15/main/pg_hba.conf
```

**3. AI Analysis Timeout**
```bash
# Increase timeout in .env
AI_ANALYSIS_TIMEOUT=120

# Check Ollama resource usage
ollama ps
```

**4. File Upload Fails**
```bash
# Check storage permissions
ls -la /var/lib/cyberdef/

# Verify nginx client_max_body_size
grep client_max_body_size /etc/nginx/sites-enabled/cyberdef
```

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Ollama health
curl http://localhost:11434/api/tags

# Database
psql -c "SELECT 1" postgresql://...
```

### Logs

```bash
# Backend logs
journalctl -u cyberdef-api -f

# Nginx access logs
tail -f /var/log/nginx/access.log

# Application logs
tail -f /opt/cyberdef/logs/cyberdef.log
```

---

## Backup & Recovery

### Database Backup
```bash
# Backup
pg_dump -U cyberdef cyberdef_prod > backup.sql

# Restore
psql -U cyberdef cyberdef_prod < backup.sql
```

### File Storage Backup
```bash
# Backup raw files
tar -czf raw_backup.tar.gz /var/lib/cyberdef/raw

# Sync to cloud
aws s3 sync /var/lib/cyberdef/raw s3://your-backup-bucket/
```

---

## Security Hardening

1. **Enable HTTPS** - Use Let's Encrypt or commercial certificates
2. **Firewall** - Only expose ports 80/443
3. **Database** - Use strong passwords, limit connections
4. **API Keys** - Implement authentication for production
5. **File Validation** - Already enforces CSV format checks
6. **Rate Limiting** - Add nginx rate limiting for uploads

```nginx
# Rate limiting example
limit_req_zone $binary_remote_addr zone=upload:10m rate=5r/m;

location /api/v1/files/upload {
    limit_req zone=upload burst=2 nodelay;
    proxy_pass http://127.0.0.1:8000;
}
```
