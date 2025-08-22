# Key Management and Workflow Handle Rotation Systems

## Overview

This document describes the comprehensive key management and workflow handle rotation systems implemented to address key expiration and workflow handle rotation requirements. These systems provide automated lifecycle management, security monitoring, and rotation capabilities for cryptographic keys and workflow handles.

## Architecture

### Key Management System

The Key Management System provides:

- **Automated Key Lifecycle Management**: Generation, rotation, expiration, and cleanup
- **Multiple Key Types**: Encryption, signing, session, and API keys
- **Secure Storage**: Encrypted key storage with master key protection
- **Monitoring**: Real-time health monitoring and alerting
- **Statistics**: Comprehensive usage and performance metrics

### Workflow Handle Rotation System

The Workflow Handle Rotation System provides:

- **Handle Lifecycle Management**: Generation, validation, rotation, and cleanup
- **Multiple Handle Types**: Session, workflow, API, and device handles
- **Anomaly Detection**: Detection of suspicious usage patterns
- **Usage Tracking**: Detailed usage pattern analysis
- **Security Policies**: Configurable security policies and thresholds

## Key Types and Configurations

### Encryption Keys
- **Algorithm**: AES-256-GCM
- **Key Length**: 32 bytes
- **Rotation Interval**: 30 days
- **Warning Threshold**: 7 days
- **Max Lifetime**: 90 days

### Signing Keys
- **Algorithm**: RSA
- **Key Length**: 2048 bits
- **Rotation Interval**: 60 days
- **Warning Threshold**: 14 days
- **Max Lifetime**: 1 year

### Session Keys
- **Algorithm**: SHA-256
- **Key Length**: 64 bytes
- **Rotation Interval**: 24 hours
- **Warning Threshold**: 2 hours
- **Max Lifetime**: 7 days

### API Keys
- **Algorithm**: SHA-512
- **Key Length**: 128 bytes
- **Rotation Interval**: 7 days
- **Warning Threshold**: 24 hours
- **Max Lifetime**: 30 days

## Handle Types and Configurations

### Session Handles
- **Algorithm**: SHA-256
- **Handle Length**: 32 bytes
- **Rotation Interval**: 1 hour
- **Warning Threshold**: 10 minutes
- **Max Lifetime**: 24 hours
- **Max Usage**: 1000

### Workflow Handles
- **Algorithm**: SHA-512
- **Handle Length**: 64 bytes
- **Rotation Interval**: 30 minutes
- **Warning Threshold**: 5 minutes
- **Max Lifetime**: 4 hours
- **Max Usage**: 100

### API Handles
- **Algorithm**: SHA-256
- **Handle Length**: 48 bytes
- **Rotation Interval**: 15 minutes
- **Warning Threshold**: 2 minutes
- **Max Lifetime**: 1 hour
- **Max Usage**: 500

### Device Handles
- **Algorithm**: SHA-384
- **Handle Length**: 56 bytes
- **Rotation Interval**: 5 minutes
- **Warning Threshold**: 1 minute
- **Max Lifetime**: 30 minutes
- **Max Usage**: 50

## API Endpoints

### Key Management Endpoints

#### Generate Key
```http
POST /api/key-management/keys/generate
Content-Type: application/json

{
  "type": "encryption|signing|session|api",
  "metadata": {
    "purpose": "string",
    "environment": "string"
  },
  "userId": "string"
}
```

#### Get Keys
```http
GET /api/key-management/keys?type=encryption&status=active&limit=50&offset=0
```

#### Get Specific Key
```http
GET /api/key-management/keys/{keyId}
```

#### Rotate Key
```http
POST /api/key-management/keys/{keyId}/rotate
Content-Type: application/json

{
  "userId": "string",
  "reason": "string"
}
```

#### Remove Key
```http
DELETE /api/key-management/keys/{keyId}
Content-Type: application/json

{
  "userId": "string",
  "reason": "string"
}
```

#### Get Key Statistics
```http
GET /api/key-management/keys/statistics
```

### Workflow Handle Endpoints

#### Generate Handle
```http
POST /api/key-management/handles/generate
Content-Type: application/json

{
  "type": "session|workflow|api|device",
  "context": {
    "environment": "string",
    "purpose": "string"
  },
  "userId": "string"
}
```

#### Get Handles
```http
GET /api/key-management/handles?type=workflow&status=active&limit=50&offset=0
```

#### Validate Handle
```http
POST /api/key-management/handles/validate
Content-Type: application/json

{
  "handleId": "string",
  "context": {
    "ip": "string",
    "userAgent": "string"
  },
  "userId": "string"
}
```

#### Rotate Handle
```http
POST /api/key-management/handles/{handleId}/rotate
Content-Type: application/json

{
  "userId": "string",
  "reason": "string"
}
```

#### Remove Handle
```http
DELETE /api/key-management/handles/{handleId}
Content-Type: application/json

{
  "userId": "string",
  "reason": "string"
}
```

#### Get Handle Statistics
```http
GET /api/key-management/handles/statistics
```

### Health and Monitoring Endpoints

#### Overall Health
```http
GET /api/key-management/health
```

#### Key Health
```http
GET /api/key-management/health/keys
```

#### Handle Health
```http
GET /api/key-management/health/handles
```

### Configuration Endpoints

#### Get Configuration
```http
GET /api/key-management/config
```

#### Update Configuration
```http
PUT /api/key-management/config
Content-Type: application/json

{
  "keyTypes": {
    "custom": {
      "algorithm": "sha256",
      "keyLength": 32,
      "rotationInterval": 86400000,
      "warningThreshold": 3600000,
      "maxLifetime": 2592000000
    }
  },
  "handleTypes": {
    "custom": {
      "algorithm": "sha256",
      "handleLength": 32,
      "rotationInterval": 3600000,
      "warningThreshold": 300000,
      "maxLifetime": 86400000,
      "maxUsage": 1000
    }
  },
  "securityPolicies": {
    "preventReuse": true,
    "enforceRotation": true,
    "trackUsage": true,
    "anomalyDetection": true,
    "rateLimitPerHandle": 100,
    "maxConcurrentHandles": 1000
  },
  "userId": "string"
}
```

## Usage Examples

### JavaScript/Node.js

```javascript
const axios = require('axios');

class KeyManager {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
  }

  // Generate a new encryption key
  async generateEncryptionKey(userId) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
      type: 'encryption',
      metadata: {
        purpose: 'data-encryption',
        environment: 'production'
      },
      userId
    });
    return response.data.key;
  }

  // Generate a workflow handle
  async generateWorkflowHandle(userId, context) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
      type: 'workflow',
      context: {
        ...context,
        environment: 'production'
      },
      userId
    });
    return response.data.handle;
  }

  // Validate a handle
  async validateHandle(handleId, userId, context) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/handles/validate`, {
      handleId,
      context: {
        ip: context.ip,
        userAgent: context.userAgent
      },
      userId
    });
    return response.data.validation;
  }

  // Get system health
  async getHealth() {
    const response = await axios.get(`${this.baseUrl}/api/key-management/health`);
    return response.data.health;
  }

  // Get statistics
  async getStatistics() {
    const [keyStats, handleStats] = await Promise.all([
      axios.get(`${this.baseUrl}/api/key-management/keys/statistics`),
      axios.get(`${this.baseUrl}/api/key-management/handles/statistics`)
    ]);
    return {
      keys: keyStats.data.statistics,
      handles: handleStats.data.statistics
    };
  }
}

// Usage example
const keyManager = new KeyManager();

async function example() {
  try {
    // Generate a key
    const key = await keyManager.generateEncryptionKey('user123');
    console.log('Generated key:', key.id);

    // Generate a handle
    const handle = await keyManager.generateWorkflowHandle('user123', {
      workflow: 'data-processing',
      session: 'session123'
    });
    console.log('Generated handle:', handle.id);

    // Validate handle
    const validation = await keyManager.validateHandle(handle.id, 'user123', {
      ip: '192.168.1.100',
      userAgent: 'MyApp/1.0'
    });
    console.log('Handle valid:', validation.valid);

    // Get health status
    const health = await keyManager.getHealth();
    console.log('System health:', health);

    // Get statistics
    const stats = await keyManager.getStatistics();
    console.log('Key statistics:', stats.keys);
    console.log('Handle statistics:', stats.handles);

  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}
```

### Python

```python
import requests
import json

class KeyManager:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url

    def generate_encryption_key(self, user_id):
        """Generate a new encryption key"""
        response = requests.post(
            f"{self.base_url}/api/key-management/keys/generate",
            json={
                "type": "encryption",
                "metadata": {
                    "purpose": "data-encryption",
                    "environment": "production"
                },
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["key"]

    def generate_workflow_handle(self, user_id, context):
        """Generate a workflow handle"""
        response = requests.post(
            f"{self.base_url}/api/key-management/handles/generate",
            json={
                "type": "workflow",
                "context": {
                    **context,
                    "environment": "production"
                },
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["handle"]

    def validate_handle(self, handle_id, user_id, context):
        """Validate a handle"""
        response = requests.post(
            f"{self.base_url}/api/key-management/handles/validate",
            json={
                "handleId": handle_id,
                "context": {
                    "ip": context["ip"],
                    "userAgent": context["userAgent"]
                },
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["validation"]

    def get_health(self):
        """Get system health"""
        response = requests.get(f"{self.base_url}/api/key-management/health")
        response.raise_for_status()
        return response.json()["health"]

    def get_statistics(self):
        """Get system statistics"""
        key_stats = requests.get(f"{self.base_url}/api/key-management/keys/statistics")
        handle_stats = requests.get(f"{self.base_url}/api/key-management/handles/statistics")
        
        key_stats.raise_for_status()
        handle_stats.raise_for_status()
        
        return {
            "keys": key_stats.json()["statistics"],
            "handles": handle_stats.json()["statistics"]
        }

# Usage example
def example():
    key_manager = KeyManager()
    
    try:
        # Generate a key
        key = key_manager.generate_encryption_key("user123")
        print(f"Generated key: {key['id']}")

        # Generate a handle
        handle = key_manager.generate_workflow_handle("user123", {
            "workflow": "data-processing",
            "session": "session123"
        })
        print(f"Generated handle: {handle['id']}")

        # Validate handle
        validation = key_manager.validate_handle(handle["id"], "user123", {
            "ip": "192.168.1.100",
            "userAgent": "MyApp/1.0"
        })
        print(f"Handle valid: {validation['valid']}")

        # Get health status
        health = key_manager.get_health()
        print(f"System health: {health}")

        # Get statistics
        stats = key_manager.get_statistics()
        print(f"Key statistics: {stats['keys']}")
        print(f"Handle statistics: {stats['handles']}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    example()
```

## Configuration

### Environment Variables

```bash
# Master key for encrypting other keys (required for production)
MASTER_KEY=your-secure-master-key-here

# Key storage directory
KEY_STORAGE_PATH=/path/to/keys

# Logging level
LOG_LEVEL=info

# Server configuration
PORT=3000
NODE_ENV=production
```

### Configuration File

The systems can be configured through the API or by modifying the default configurations in the source code:

```javascript
// Key Management System Configuration
const keyTypes = {
  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    rotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
    warningThreshold: 7 * 24 * 60 * 60 * 1000, // 7 days
    maxLifetime: 90 * 24 * 60 * 60 * 1000 // 90 days
  }
  // ... other key types
};

// Workflow Handle Rotation System Configuration
const handleTypes = {
  workflow: {
    algorithm: 'sha512',
    handleLength: 64,
    rotationInterval: 30 * 60 * 1000, // 30 minutes
    warningThreshold: 5 * 60 * 1000, // 5 minutes
    maxLifetime: 4 * 60 * 60 * 1000, // 4 hours
    maxUsage: 100
  }
  // ... other handle types
};

// Security Policies
const securityPolicies = {
  preventReuse: true,
  enforceRotation: true,
  trackUsage: true,
  anomalyDetection: true,
  rateLimitPerHandle: 100,
  maxConcurrentHandles: 1000
};
```

## Monitoring and Alerting

### Health Checks

The systems provide comprehensive health monitoring:

- **Key Health**: Active keys, expiring keys, rotation queue
- **Handle Health**: Active handles, expiring handles, usage patterns
- **System Health**: Overall system status and component health

### Statistics

Detailed statistics are available for:

- **Key Statistics**: Total keys, active keys, usage patterns, rotation history
- **Handle Statistics**: Total handles, active handles, usage patterns, anomaly detection
- **Performance Metrics**: Generation times, validation times, error rates

### Logging

The systems provide comprehensive logging:

- **Access Logs**: All API access and operations
- **Audit Logs**: Security-relevant events (key generation, rotation, removal)
- **Error Logs**: System errors and failures
- **Security Logs**: Security events and anomalies

## Security Features

### Key Security

- **Encrypted Storage**: All keys are encrypted before storage
- **Master Key Protection**: Keys are encrypted with a master key
- **Access Control**: Key access is logged and monitored
- **Automatic Rotation**: Keys are automatically rotated based on schedule
- **Expiration Handling**: Expired keys are automatically replaced

### Handle Security

- **Usage Tracking**: All handle usage is tracked and analyzed
- **Anomaly Detection**: Suspicious usage patterns are detected
- **Rate Limiting**: Usage is rate-limited per handle
- **Automatic Rotation**: Handles are automatically rotated
- **Context Validation**: Handle usage is validated against context

### General Security

- **Input Validation**: All inputs are validated and sanitized
- **Rate Limiting**: API endpoints are rate-limited
- **Audit Logging**: All operations are logged for audit
- **Error Handling**: Secure error handling without information leakage
- **CORS Protection**: Cross-origin requests are properly handled

## Best Practices

### Key Management

1. **Use Appropriate Key Types**: Choose the right key type for your use case
2. **Monitor Key Health**: Regularly check key health and statistics
3. **Plan for Rotation**: Ensure your application can handle key rotation
4. **Secure Master Key**: Keep the master key secure and backed up
5. **Monitor Usage**: Track key usage patterns for anomalies

### Handle Management

1. **Use Appropriate Handle Types**: Choose the right handle type for your workflow
2. **Validate Context**: Always provide proper context for handle validation
3. **Monitor Usage**: Track handle usage for anomalies
4. **Handle Rotation**: Be prepared for automatic handle rotation
5. **Error Handling**: Handle validation failures gracefully

### General

1. **Secure Communication**: Use HTTPS for all API communication
2. **Authentication**: Implement proper authentication for API access
3. **Authorization**: Implement proper authorization for operations
4. **Monitoring**: Set up monitoring and alerting for the systems
5. **Backup**: Regularly backup configuration and metadata
6. **Testing**: Test key and handle rotation scenarios
7. **Documentation**: Document your usage patterns and configurations

## Troubleshooting

### Common Issues

1. **Key Not Found**: Check if the key exists and is active
2. **Handle Invalid**: Check if the handle is valid and not expired
3. **Rotation Failures**: Check system health and configuration
4. **Performance Issues**: Monitor statistics and adjust configuration
5. **Security Alerts**: Review logs and investigate anomalies

### Debugging

1. **Enable Debug Logging**: Set LOG_LEVEL=debug
2. **Check Health Endpoints**: Use health endpoints to diagnose issues
3. **Review Statistics**: Check statistics for usage patterns
4. **Monitor Logs**: Review logs for errors and warnings
5. **Test Endpoints**: Use test endpoints to verify functionality

## Testing

### Running Tests

```bash
# Install dependencies
npm install

# Run the test suite
node test-key-workflow-rotation.js

# Run with custom base URL
node test-key-workflow-rotation.js http://your-server:3000
```

### Test Coverage

The test suite covers:

- **Health Checks**: System health and component health
- **Key Management**: Generation, retrieval, rotation, removal
- **Handle Management**: Generation, validation, rotation, removal
- **Expiration Scenarios**: Key and handle expiration handling
- **Rotation Scenarios**: Manual and automatic rotation
- **Anomaly Detection**: Suspicious usage pattern detection
- **Configuration Management**: Configuration updates and retrieval
- **Statistics and Monitoring**: Statistics and health monitoring
- **Error Handling**: Error scenarios and edge cases
- **Performance Testing**: Load testing and performance validation

## Deployment

### Production Deployment

1. **Set Master Key**: Set a secure MASTER_KEY environment variable
2. **Configure Storage**: Set up secure key storage directory
3. **Enable Logging**: Configure appropriate logging levels
4. **Set Up Monitoring**: Configure monitoring and alerting
5. **Test Rotation**: Test key and handle rotation scenarios
6. **Backup Configuration**: Set up configuration backup
7. **Security Review**: Perform security review of configuration

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["node", "src/index.js"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  key-management:
    build: .
    ports:
      - "3000:3000"
    environment:
      - MASTER_KEY=${MASTER_KEY}
      - NODE_ENV=production
      - LOG_LEVEL=info
    volumes:
      - key-storage:/app/keys
    restart: unless-stopped

volumes:
  key-storage:
```

## Support

For support and questions:

1. **Documentation**: Review this documentation thoroughly
2. **Logs**: Check system logs for error messages
3. **Health Checks**: Use health endpoints to diagnose issues
4. **Testing**: Run the test suite to verify functionality
5. **Configuration**: Review and adjust configuration as needed

## Changelog

### Version 1.0.0
- Initial implementation of Key Management System
- Initial implementation of Workflow Handle Rotation System
- Comprehensive API endpoints
- Health monitoring and statistics
- Configuration management
- Security features and best practices
- Comprehensive testing suite
- Documentation and examples
