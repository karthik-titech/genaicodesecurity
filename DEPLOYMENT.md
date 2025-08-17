# Deployment Guide

This guide covers deploying the Google Home Security Patch to various environments and platforms.

## 🚀 Quick Deployment

### Local Development

```bash
# Clone and setup
git clone https://github.com/your-repo/google-home-security-patch.git
cd google-home-security-patch
npm install

# Configure environment
cp env.example .env
# Edit .env with your settings

# Start development server
npm run dev
```

### Production Deployment

```bash
# Install dependencies
npm ci --only=production

# Set environment variables
export NODE_ENV=production
export PORT=3000

# Start the application
npm start
```

## 🐳 Docker Deployment

### Dockerfile

```dockerfile
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S security-patch -u 1001

# Change ownership
RUN chown -R security-patch:nodejs /usr/src/app
USER security-patch

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  security-patch:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
    env_file:
      - .env
    volumes:
      - ./logs:/usr/src/app/logs
      - ./config:/usr/src/app/config
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

### Build and Run

```bash
# Build the image
docker build -t google-home-security-patch .

# Run with docker-compose
docker-compose up -d

# Check logs
docker-compose logs -f security-patch
```

## ☁️ Cloud Deployment

### AWS Deployment

#### EC2 Instance

```bash
# Launch EC2 instance (Ubuntu 20.04)
# Connect via SSH

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Clone repository
git clone https://github.com/your-repo/google-home-security-patch.git
cd google-home-security-patch

# Install dependencies
npm ci --only=production

# Configure environment
cp env.example .env
# Edit .env with production settings

# Start with PM2
pm2 start src/index.js --name "security-patch"

# Save PM2 configuration
pm2 save
pm2 startup
```

#### AWS ECS

```yaml
# task-definition.json
{
  "family": "security-patch",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "security-patch",
      "image": "your-account.dkr.ecr.region.amazonaws.com/security-patch:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "GOOGLE_HOME_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:google-home-api-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/security-patch",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Platform

#### App Engine

```yaml
# app.yaml
runtime: nodejs18

env_variables:
  NODE_ENV: production
  PORT: 8080

automatic_scaling:
  target_cpu_utilization: 0.65
  min_instances: 1
  max_instances: 10

handlers:
  - url: /.*
    script: auto
    secure: always
```

#### Cloud Run

```bash
# Build and deploy to Cloud Run
gcloud builds submit --tag gcr.io/PROJECT_ID/security-patch
gcloud run deploy security-patch \
  --image gcr.io/PROJECT_ID/security-patch \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production
```

### Azure

#### Azure App Service

```bash
# Deploy to Azure App Service
az webapp create --resource-group myResourceGroup --plan myAppServicePlan --name security-patch --runtime "NODE|18-lts"

# Configure environment variables
az webapp config appsettings set --resource-group myResourceGroup --name security-patch --settings NODE_ENV=production

# Deploy code
az webapp deployment source config-local-git --resource-group myResourceGroup --name security-patch
git remote add azure <git-url-from-previous-command>
git push azure main
```

## 🔧 Environment Configuration

### Production Environment Variables

```bash
# Server Configuration
NODE_ENV=production
PORT=3000

# Security Configuration
STRICT_MODE=true
MAX_CONTEXT_SIZE=5000
MAX_TOOL_CHAINING=1

# Logging
LOG_LEVEL=warn

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://api.yourdomain.com

# Database
DATABASE_URL=postgresql://user:password@host:port/database

# Monitoring
ALERT_WEBHOOK_URL=https://your-monitoring-service.com/webhook
SECURITY_EMAIL=security@yourcompany.com

# API Keys (use secrets management)
GOOGLE_HOME_API_KEY=your_api_key
GOOGLE_CALENDAR_API_KEY=your_calendar_key
```

### Secrets Management

#### AWS Secrets Manager

```bash
# Store secrets
aws secretsmanager create-secret \
  --name "security-patch/google-home-api-key" \
  --description "Google Home API Key" \
  --secret-string "your-api-key-here"

# Retrieve in application
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName) {
  const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
  return JSON.parse(data.SecretString);
}
```

#### Google Secret Manager

```bash
# Create secret
echo -n "your-api-key" | gcloud secrets create google-home-api-key --data-file=-

# Access in application
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const client = new SecretManagerServiceClient();

async function getSecret(secretName) {
  const [version] = await client.accessSecretVersion({
    name: `projects/PROJECT_ID/secrets/${secretName}/versions/latest`,
  });
  return version.payload.data.toString();
}
```

## 📊 Monitoring and Logging

### Application Monitoring

```javascript
// Add monitoring to your application
const winston = require('winston');
const Sentry = require('@sentry/node');

// Initialize Sentry
Sentry.init({
  dsn: 'your-sentry-dsn',
  environment: process.env.NODE_ENV,
});

// Enhanced logging
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});
```

### Health Checks

```bash
# Health check endpoint
curl http://your-domain.com/health

# Expected response
{
  "status": "healthy",
  "security": "active",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### Metrics Collection

```javascript
// Add metrics collection
const prometheus = require('prom-client');
const express = require('express');

// Create metrics
const httpRequestDurationMicroseconds = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
});

const httpRequestsTotal = new prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});
```

## 🔒 Security Hardening

### SSL/TLS Configuration

```javascript
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('/path/to/private-key.pem'),
  cert: fs.readFileSync('/path/to/certificate.pem'),
  ca: fs.readFileSync('/path/to/ca-bundle.pem')
};

https.createServer(options, app).listen(443);
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 3000/tcp  # Don't expose directly
sudo ufw enable

# iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
```

### Process Management

```bash
# PM2 configuration
pm2 ecosystem

# ecosystem.config.js
module.exports = {
  apps: [{
    name: 'security-patch',
    script: 'src/index.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
};
```

## 🚨 Disaster Recovery

### Backup Strategy

```bash
# Database backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# Configuration backup
tar -czf config_backup_$(date +%Y%m%d_%H%M%S).tar.gz config/

# Log backup
tar -czf logs_backup_$(date +%Y%m%d_%H%M%S).tar.gz logs/
```

### Recovery Procedures

```bash
# Restore from backup
psql $DATABASE_URL < backup_20240101_120000.sql

# Restart services
pm2 restart all

# Verify health
curl http://localhost:3000/health
```

## 📈 Scaling

### Horizontal Scaling

```bash
# Load balancer configuration (nginx)
upstream security_patch {
    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    server 127.0.0.1:3003;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://security_patch;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Auto-scaling

```bash
# PM2 cluster mode
pm2 start src/index.js -i max --name "security-patch"

# Docker Swarm
docker service create --name security-patch --replicas 3 your-image
```

This deployment guide covers the most common deployment scenarios. Choose the approach that best fits your infrastructure and requirements.
