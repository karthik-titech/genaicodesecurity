# Quick Start Guide: Key Management & Workflow Handle Rotation

## Overview

This quick start guide will help you get the Key Management and Workflow Handle Rotation systems up and running in minutes.

## Prerequisites

- Node.js 18+ installed
- npm or yarn package manager
- Basic understanding of REST APIs

## Installation

1. **Clone the repository** (if not already done):
```bash
git clone <repository-url>
cd genaicodesecurity
```

2. **Install dependencies**:
```bash
npm install
```

3. **Set up environment variables**:
```bash
cp env.example .env
```

Edit `.env` and add:
```bash
# Required for production
MASTER_KEY=your-secure-32-byte-master-key-here

# Optional configurations
PORT=3000
NODE_ENV=development
LOG_LEVEL=info
```

4. **Start the server**:
```bash
npm start
```

The server will start on `http://localhost:3000` with all systems active.

## Quick Test

Run the comprehensive test suite to verify everything is working:

```bash
npm run test-key-workflow
```

This will test all key management and workflow handle rotation functionality.

## Basic Usage

### 1. Check System Health

```bash
curl http://localhost:3000/api/key-management/health
```

Expected response:
```json
{
  "success": true,
  "health": {
    "keyManagement": {
      "active": true,
      "totalKeys": 4
    },
    "workflowHandles": {
      "active": true,
      "totalHandles": 0
    }
  }
}
```

### 2. Generate a Key

```bash
curl -X POST http://localhost:3000/api/key-management/keys/generate \
  -H "Content-Type: application/json" \
  -d '{
    "type": "encryption",
    "metadata": {
      "purpose": "testing",
      "environment": "development"
    },
    "userId": "test-user"
  }'
```

### 3. Generate a Workflow Handle

```bash
curl -X POST http://localhost:3000/api/key-management/handles/generate \
  -H "Content-Type: application/json" \
  -d '{
    "type": "workflow",
    "context": {
      "workflow": "data-processing",
      "session": "test-session"
    },
    "userId": "test-user"
  }'
```

### 4. Validate a Handle

```bash
curl -X POST http://localhost:3000/api/key-management/handles/validate \
  -H "Content-Type: application/json" \
  -d '{
    "handleId": "your-handle-id-here",
    "context": {
      "ip": "127.0.0.1",
      "userAgent": "curl/7.68.0"
    },
    "userId": "test-user"
  }'
```

### 5. Get Statistics

```bash
# Key statistics
curl http://localhost:3000/api/key-management/keys/statistics

# Handle statistics
curl http://localhost:3000/api/key-management/handles/statistics
```

## JavaScript Client Example

```javascript
const axios = require('axios');

class KeyManager {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
  }

  async generateKey(type, userId, metadata = {}) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
      type,
      metadata,
      userId
    });
    return response.data.key;
  }

  async generateHandle(type, userId, context = {}) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
      type,
      context,
      userId
    });
    return response.data.handle;
  }

  async validateHandle(handleId, userId, context = {}) {
    const response = await axios.post(`${this.baseUrl}/api/key-management/handles/validate`, {
      handleId,
      context,
      userId
    });
    return response.data.validation;
  }
}

// Usage
const keyManager = new KeyManager();

async function example() {
  try {
    // Generate an encryption key
    const key = await keyManager.generateKey('encryption', 'user123', {
      purpose: 'data-encryption'
    });
    console.log('Generated key:', key.id);

    // Generate a workflow handle
    const handle = await keyManager.generateHandle('workflow', 'user123', {
      workflow: 'data-processing'
    });
    console.log('Generated handle:', handle.id);

    // Validate the handle
    const validation = await keyManager.validateHandle(handle.id, 'user123', {
      ip: '192.168.1.100',
      userAgent: 'MyApp/1.0'
    });
    console.log('Handle valid:', validation.valid);

  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

example();
```

## Python Client Example

```python
import requests

class KeyManager:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url

    def generate_key(self, key_type, user_id, metadata=None):
        if metadata is None:
            metadata = {}
        
        response = requests.post(
            f"{self.base_url}/api/key-management/keys/generate",
            json={
                "type": key_type,
                "metadata": metadata,
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["key"]

    def generate_handle(self, handle_type, user_id, context=None):
        if context is None:
            context = {}
        
        response = requests.post(
            f"{self.base_url}/api/key-management/handles/generate",
            json={
                "type": handle_type,
                "context": context,
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["handle"]

    def validate_handle(self, handle_id, user_id, context=None):
        if context is None:
            context = {}
        
        response = requests.post(
            f"{self.base_url}/api/key-management/handles/validate",
            json={
                "handleId": handle_id,
                "context": context,
                "userId": user_id
            }
        )
        response.raise_for_status()
        return response.json()["validation"]

# Usage
def main():
    key_manager = KeyManager()
    
    try:
        # Generate an encryption key
        key = key_manager.generate_key("encryption", "user123", {
            "purpose": "data-encryption"
        })
        print(f"Generated key: {key['id']}")

        # Generate a workflow handle
        handle = key_manager.generate_handle("workflow", "user123", {
            "workflow": "data-processing"
        })
        print(f"Generated handle: {handle['id']}")

        # Validate the handle
        validation = key_manager.validate_handle(handle["id"], "user123", {
            "ip": "192.168.1.100",
            "userAgent": "MyApp/1.0"
        })
        print(f"Handle valid: {validation['valid']}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## Key Types Available

- **encryption**: AES-256-GCM keys for data encryption
- **signing**: RSA keys for digital signatures
- **session**: SHA-256 keys for session management
- **api**: SHA-512 keys for API authentication

## Handle Types Available

- **session**: Short-lived session handles (1 hour rotation)
- **workflow**: Workflow execution handles (30 min rotation)
- **api**: API access handles (15 min rotation)
- **device**: Device control handles (5 min rotation)

## Configuration

### View Current Configuration

```bash
curl http://localhost:3000/api/key-management/config
```

### Update Configuration

```bash
curl -X PUT http://localhost:3000/api/key-management/config \
  -H "Content-Type: application/json" \
  -d '{
    "keyTypes": {
      "custom": {
        "algorithm": "sha256",
        "keyLength": 32,
        "rotationInterval": 86400000,
        "warningThreshold": 3600000,
        "maxLifetime": 2592000000
      }
    },
    "userId": "admin"
  }'
```

## Monitoring

### Health Checks

```bash
# Overall health
curl http://localhost:3000/api/key-management/health

# Key health
curl http://localhost:3000/api/key-management/health/keys

# Handle health
curl http://localhost:3000/api/key-management/health/handles
```

### Statistics

```bash
# Key statistics
curl http://localhost:3000/api/key-management/keys/statistics

# Handle statistics
curl http://localhost:3000/api/key-management/handles/statistics
```

## Common Operations

### List All Keys

```bash
curl "http://localhost:3000/api/key-management/keys?limit=10&offset=0"
```

### List All Handles

```bash
curl "http://localhost:3000/api/key-management/handles?limit=10&offset=0"
```

### Rotate a Key

```bash
curl -X POST http://localhost:3000/api/key-management/keys/{keyId}/rotate \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "admin",
    "reason": "security-update"
  }'
```

### Rotate a Handle

```bash
curl -X POST http://localhost:3000/api/key-management/handles/{handleId}/rotate \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "admin",
    "reason": "security-update"
  }'
```

## Troubleshooting

### Check Logs

The system logs all operations. Check the console output for:
- System startup messages
- Key and handle generation logs
- Error messages
- Health check results

### Common Issues

1. **"Key Management System not available"**
   - Ensure the server is running
   - Check that the MASTER_KEY environment variable is set

2. **"Handle not found or inactive"**
   - The handle may have expired
   - Check handle statistics for active handles

3. **"Key expired"**
   - Keys automatically expire based on configuration
   - Generate a new key or check rotation settings

4. **Validation errors**
   - Ensure all required fields are provided
   - Check input validation rules

### Debug Mode

Enable debug logging by setting:
```bash
LOG_LEVEL=debug
```

## Next Steps

1. **Read the full documentation**: See `docs/KEY_MANAGEMENT_WORKFLOW.md`
2. **Run the test suite**: `npm run test-key-workflow`
3. **Explore the API**: Use the endpoints listed above
4. **Configure for production**: Set up proper authentication and monitoring
5. **Integrate with your application**: Use the client examples as starting points

## Support

- **Documentation**: `docs/KEY_MANAGEMENT_WORKFLOW.md`
- **API Reference**: See the documentation for complete endpoint details
- **Examples**: Check the client examples above
- **Testing**: Run `npm run test-key-workflow` for comprehensive testing

## Security Notes

⚠️ **Important Security Considerations**:

1. **Master Key**: Keep your MASTER_KEY secure and backed up
2. **Environment**: Use HTTPS in production
3. **Authentication**: Implement proper authentication for API access
4. **Monitoring**: Set up monitoring for key and handle usage
5. **Rotation**: Monitor automatic rotation and handle failures gracefully
6. **Backup**: Regularly backup key metadata and configuration

The systems are designed with security in mind, but proper deployment and configuration are essential for production use.
