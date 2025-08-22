const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const NodeCache = require('node-cache');
const Logger = require('../utils/Logger');

class KeyManagementSystem {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Key storage and cache
    this.keyCache = new NodeCache({
      stdTTL: 3600, // 1 hour default TTL
      checkperiod: 300
    });
    
    // Key rotation schedule cache
    this.rotationCache = new NodeCache({
      stdTTL: 86400, // 24 hours default TTL
      checkperiod: 3600
    });
    
    // Key types and their configurations
    this.keyTypes = {
      encryption: {
        algorithm: 'aes-256-gcm',
        keyLength: 32,
        rotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
        warningThreshold: 7 * 24 * 60 * 60 * 1000, // 7 days
        maxLifetime: 90 * 24 * 60 * 60 * 1000 // 90 days
      },
      signing: {
        algorithm: 'rsa',
        keyLength: 2048,
        rotationInterval: 60 * 24 * 60 * 60 * 1000, // 60 days
        warningThreshold: 14 * 24 * 60 * 60 * 1000, // 14 days
        maxLifetime: 365 * 24 * 60 * 60 * 1000 // 1 year
      },
      session: {
        algorithm: 'sha256',
        keyLength: 64,
        rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
        warningThreshold: 2 * 60 * 60 * 1000, // 2 hours
        maxLifetime: 7 * 24 * 60 * 60 * 1000 // 7 days
      },
      api: {
        algorithm: 'sha512',
        keyLength: 128,
        rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
        warningThreshold: 24 * 60 * 60 * 1000, // 24 hours
        maxLifetime: 30 * 24 * 60 * 60 * 1000 // 30 days
      }
    };
    
    // Key storage paths
    this.keyStoragePath = path.join(__dirname, '../../keys');
    this.keyMetadataPath = path.join(this.keyStoragePath, 'metadata.json');
    
    // Active keys registry
    this.activeKeys = new Map();
    
    // Key rotation queue
    this.rotationQueue = [];
    
    // Monitoring intervals
    this.monitoringIntervals = new Map();
  }

  async initialize() {
    try {
      this.logger.info('Initializing Key Management System...');
      
      // Create key storage directory
      if (!fs.existsSync(this.keyStoragePath)) {
        fs.mkdirSync(this.keyStoragePath, { recursive: true });
        this.logger.info('Created key storage directory');
      }
      
      // Load existing keys and metadata
      await this.loadExistingKeys();
      
      // Set up cache event listeners
      this.setupCacheListeners();
      
      // Start key monitoring
      this.startKeyMonitoring();
      
      // Initialize key rotation scheduler
      this.initializeRotationScheduler();
      
      this.isActive = true;
      this.logger.info('Key Management System initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Key Management System:', error);
      throw error;
    }
  }

  async loadExistingKeys() {
    try {
      // Load key metadata if it exists
      if (fs.existsSync(this.keyMetadataPath)) {
        const metadata = JSON.parse(fs.readFileSync(this.keyMetadataPath, 'utf8'));
        
        for (const [keyId, keyInfo] of Object.entries(metadata)) {
          if (this.isKeyValid(keyInfo)) {
            this.activeKeys.set(keyId, keyInfo);
            this.keyCache.set(keyId, keyInfo);
            
            // Check if key needs rotation
            if (this.shouldRotateKey(keyInfo)) {
              this.rotationQueue.push({
                keyId,
                keyType: keyInfo.type,
                priority: this.getRotationPriority(keyInfo),
                scheduledTime: keyInfo.createdAt + keyInfo.rotationInterval
              });
            }
          } else {
            this.logger.warn(`Removing expired key: ${keyId}`);
            await this.removeKey(keyId);
          }
        }
      }
      
      // Generate initial keys if none exist
      if (this.activeKeys.size === 0) {
        await this.generateInitialKeys();
      }
      
    } catch (error) {
      this.logger.error('Error loading existing keys:', error);
      throw error;
    }
  }

  async generateInitialKeys() {
    this.logger.info('Generating initial keys...');
    
    for (const [keyType, config] of Object.entries(this.keyTypes)) {
      await this.generateKey(keyType);
    }
  }

  async generateKey(keyType, options = {}) {
    try {
      const config = this.keyTypes[keyType];
      if (!config) {
        throw new Error(`Unknown key type: ${keyType}`);
      }
      
      const keyId = this.generateKeyId(keyType);
      const keyData = await this.createKey(keyType, config);
      
      const keyInfo = {
        id: keyId,
        type: keyType,
        algorithm: config.algorithm,
        keyLength: config.keyLength,
        createdAt: Date.now(),
        expiresAt: Date.now() + config.maxLifetime,
        rotationInterval: config.rotationInterval,
        warningThreshold: config.warningThreshold,
        maxLifetime: config.maxLifetime,
        isActive: true,
        usageCount: 0,
        lastUsed: null,
        metadata: options.metadata || {}
      };
      
      // Store key data securely
      await this.storeKey(keyId, keyData, keyInfo);
      
      // Add to active keys
      this.activeKeys.set(keyId, keyInfo);
      this.keyCache.set(keyId, keyInfo);
      
      // Schedule rotation
      this.scheduleKeyRotation(keyId, keyInfo);
      
      this.logger.info(`Generated new ${keyType} key: ${keyId}`);
      
      return keyInfo;
      
    } catch (error) {
      this.logger.error(`Error generating ${keyType} key:`, error);
      throw error;
    }
  }

  async createKey(keyType, config) {
    switch (keyType) {
      case 'encryption':
        return crypto.randomBytes(config.keyLength);
        
      case 'signing':
        return crypto.generateKeyPairSync('rsa', {
          modulusLength: config.keyLength,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
      case 'session':
        return crypto.randomBytes(config.keyLength);
        
      case 'api':
        return crypto.randomBytes(config.keyLength);
        
      default:
        throw new Error(`Unsupported key type: ${keyType}`);
    }
  }

  async storeKey(keyId, keyData, keyInfo) {
    try {
      const keyPath = path.join(this.keyStoragePath, `${keyId}.key`);
      
      // Encrypt key data before storage
      const encryptedData = await this.encryptKeyData(keyData);
      
      // Store encrypted key
      fs.writeFileSync(keyPath, encryptedData);
      
      // Update metadata
      await this.updateKeyMetadata();
      
    } catch (error) {
      this.logger.error(`Error storing key ${keyId}:`, error);
      throw error;
    }
  }

  async encryptKeyData(keyData) {
    // Use a master key for encrypting other keys
    const masterKey = process.env.MASTER_KEY || crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher('aes-256-gcm', masterKey);
    cipher.setAAD(Buffer.from('key-encryption'));
    
    let encrypted = cipher.update(keyData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    });
  }

  async getKey(keyId) {
    try {
      // Check cache first
      let keyInfo = this.keyCache.get(keyId);
      
      if (!keyInfo) {
        keyInfo = this.activeKeys.get(keyId);
        if (keyInfo) {
          this.keyCache.set(keyId, keyInfo);
        }
      }
      
      if (!keyInfo || !keyInfo.isActive) {
        throw new Error(`Key not found or inactive: ${keyId}`);
      }
      
      // Check if key is expired
      if (this.isKeyExpired(keyInfo)) {
        await this.handleKeyExpiration(keyId);
        throw new Error(`Key expired: ${keyId}`);
      }
      
      // Update usage statistics
      keyInfo.usageCount++;
      keyInfo.lastUsed = Date.now();
      
      // Load key data
      const keyData = await this.loadKeyData(keyId);
      
      return {
        keyInfo,
        keyData
      };
      
    } catch (error) {
      this.logger.error(`Error getting key ${keyId}:`, error);
      throw error;
    }
  }

  async loadKeyData(keyId) {
    try {
      const keyPath = path.join(this.keyStoragePath, `${keyId}.key`);
      
      if (!fs.existsSync(keyPath)) {
        throw new Error(`Key file not found: ${keyId}`);
      }
      
      const encryptedData = fs.readFileSync(keyPath, 'utf8');
      const keyData = await this.decryptKeyData(encryptedData);
      
      return keyData;
      
    } catch (error) {
      this.logger.error(`Error loading key data for ${keyId}:`, error);
      throw error;
    }
  }

  async decryptKeyData(encryptedData) {
    const masterKey = process.env.MASTER_KEY || crypto.randomBytes(32);
    const { encrypted, iv, authTag } = JSON.parse(encryptedData);
    
    const decipher = crypto.createDecipher('aes-256-gcm', masterKey);
    decipher.setAAD(Buffer.from('key-encryption'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  async rotateKey(keyId) {
    try {
      const keyInfo = this.activeKeys.get(keyId);
      if (!keyInfo) {
        throw new Error(`Key not found: ${keyId}`);
      }
      
      this.logger.info(`Starting key rotation for: ${keyId}`);
      
      // Generate new key
      const newKeyInfo = await this.generateKey(keyInfo.type, {
        metadata: {
          rotatedFrom: keyId,
          rotationReason: 'scheduled'
        }
      });
      
      // Mark old key for deprecation
      keyInfo.isActive = false;
      keyInfo.deprecatedAt = Date.now();
      keyInfo.replacedBy = newKeyInfo.id;
      
      // Keep old key for a grace period
      setTimeout(async () => {
        await this.removeKey(keyId);
      }, 24 * 60 * 60 * 1000); // 24 hours grace period
      
      this.logger.info(`Key rotation completed: ${keyId} -> ${newKeyInfo.id}`);
      
      return newKeyInfo;
      
    } catch (error) {
      this.logger.error(`Error rotating key ${keyId}:`, error);
      throw error;
    }
  }

  async handleKeyExpiration(keyId) {
    try {
      this.logger.warn(`Handling key expiration: ${keyId}`);
      
      const keyInfo = this.activeKeys.get(keyId);
      if (!keyInfo) {
        return;
      }
      
      // Mark as expired
      keyInfo.isActive = false;
      keyInfo.expiredAt = Date.now();
      
      // Generate replacement key
      await this.generateKey(keyInfo.type, {
        metadata: {
          rotatedFrom: keyId,
          rotationReason: 'expiration'
        }
      });
      
      // Remove expired key after grace period
      setTimeout(async () => {
        await this.removeKey(keyId);
      }, 60 * 60 * 1000); // 1 hour grace period
      
    } catch (error) {
      this.logger.error(`Error handling key expiration for ${keyId}:`, error);
    }
  }

  async removeKey(keyId) {
    try {
      // Remove from active keys
      this.activeKeys.delete(keyId);
      this.keyCache.del(keyId);
      
      // Remove key file
      const keyPath = path.join(this.keyStoragePath, `${keyId}.key`);
      if (fs.existsSync(keyPath)) {
        fs.unlinkSync(keyPath);
      }
      
      // Update metadata
      await this.updateKeyMetadata();
      
      this.logger.info(`Removed key: ${keyId}`);
      
    } catch (error) {
      this.logger.error(`Error removing key ${keyId}:`, error);
    }
  }

  async updateKeyMetadata() {
    try {
      const metadata = {};
      
      for (const [keyId, keyInfo] of this.activeKeys) {
        metadata[keyId] = keyInfo;
      }
      
      fs.writeFileSync(this.keyMetadataPath, JSON.stringify(metadata, null, 2));
      
    } catch (error) {
      this.logger.error('Error updating key metadata:', error);
    }
  }

  setupCacheListeners() {
    this.keyCache.on('expired', (key, value) => {
      this.logger.info(`Key cache expired: ${key}`);
    });
    
    this.rotationCache.on('expired', (key, value) => {
      this.logger.info(`Rotation cache expired: ${key}`);
    });
  }

  startKeyMonitoring() {
    // Monitor key expiration every 5 minutes
    this.monitoringIntervals.set('expiration', setInterval(() => {
      this.checkKeyExpiration();
    }, 5 * 60 * 1000));
    
    // Monitor key rotation every hour
    this.monitoringIntervals.set('rotation', setInterval(() => {
      this.processRotationQueue();
    }, 60 * 60 * 1000));
    
    // Monitor key health every 15 minutes
    this.monitoringIntervals.set('health', setInterval(() => {
      this.checkKeyHealth();
    }, 15 * 60 * 1000));
  }

  async checkKeyExpiration() {
    try {
      const now = Date.now();
      
      for (const [keyId, keyInfo] of this.activeKeys) {
        if (keyInfo.expiresAt && now >= keyInfo.expiresAt) {
          await this.handleKeyExpiration(keyId);
        } else if (keyInfo.expiresAt && (keyInfo.expiresAt - now) <= keyInfo.warningThreshold) {
          this.logger.warn(`Key ${keyId} will expire soon: ${new Date(keyInfo.expiresAt).toISOString()}`);
        }
      }
      
    } catch (error) {
      this.logger.error('Error checking key expiration:', error);
    }
  }

  async processRotationQueue() {
    try {
      if (this.rotationQueue.length === 0) {
        return;
      }
      
      // Sort by priority and scheduled time
      this.rotationQueue.sort((a, b) => {
        if (a.priority !== b.priority) {
          return b.priority - a.priority;
        }
        return a.scheduledTime - b.scheduledTime;
      });
      
      const now = Date.now();
      const keysToRotate = this.rotationQueue.filter(item => item.scheduledTime <= now);
      
      for (const item of keysToRotate) {
        try {
          await this.rotateKey(item.keyId);
          this.rotationQueue = this.rotationQueue.filter(q => q.keyId !== item.keyId);
        } catch (error) {
          this.logger.error(`Failed to rotate key ${item.keyId}:`, error);
        }
      }
      
    } catch (error) {
      this.logger.error('Error processing rotation queue:', error);
    }
  }

  async checkKeyHealth() {
    try {
      const healthReport = {
        totalKeys: this.activeKeys.size,
        activeKeys: 0,
        expiringKeys: 0,
        expiredKeys: 0,
        rotationQueue: this.rotationQueue.length,
        keyTypes: {}
      };
      
      const now = Date.now();
      
      for (const [keyId, keyInfo] of this.activeKeys) {
        if (keyInfo.isActive) {
          healthReport.activeKeys++;
          
          if (!healthReport.keyTypes[keyInfo.type]) {
            healthReport.keyTypes[keyInfo.type] = 0;
          }
          healthReport.keyTypes[keyInfo.type]++;
          
          if (keyInfo.expiresAt && (keyInfo.expiresAt - now) <= keyInfo.warningThreshold) {
            healthReport.expiringKeys++;
          }
        } else {
          healthReport.expiredKeys++;
        }
      }
      
      this.logger.info('Key health report:', healthReport);
      
    } catch (error) {
      this.logger.error('Error checking key health:', error);
    }
  }

  scheduleKeyRotation(keyId, keyInfo) {
    const rotationTime = keyInfo.createdAt + keyInfo.rotationInterval;
    const priority = this.getRotationPriority(keyInfo);
    
    this.rotationQueue.push({
      keyId,
      keyType: keyInfo.type,
      priority,
      scheduledTime: rotationTime
    });
  }

  getRotationPriority(keyInfo) {
    // Higher priority for keys that are expiring soon
    const timeToExpiry = keyInfo.expiresAt - Date.now();
    const timeToRotation = (keyInfo.createdAt + keyInfo.rotationInterval) - Date.now();
    
    if (timeToExpiry < 24 * 60 * 60 * 1000) { // Less than 24 hours
      return 10;
    } else if (timeToExpiry < 7 * 24 * 60 * 60 * 1000) { // Less than 7 days
      return 8;
    } else if (timeToRotation < 0) { // Overdue for rotation
      return 6;
    } else if (timeToRotation < 24 * 60 * 60 * 1000) { // Due within 24 hours
      return 4;
    } else {
      return 2;
    }
  }

  isKeyValid(keyInfo) {
    return keyInfo.isActive && 
           keyInfo.expiresAt > Date.now() &&
           keyInfo.createdAt + keyInfo.maxLifetime > Date.now();
  }

  isKeyExpired(keyInfo) {
    return !keyInfo.isActive || keyInfo.expiresAt <= Date.now();
  }

  shouldRotateKey(keyInfo) {
    const now = Date.now();
    return (keyInfo.createdAt + keyInfo.rotationInterval) <= now;
  }

  generateKeyId(keyType) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    return `${keyType}_${timestamp}_${random}`;
  }

  getActiveKeysByType(keyType) {
    const keys = [];
    for (const [keyId, keyInfo] of this.activeKeys) {
      if (keyInfo.type === keyType && keyInfo.isActive) {
        keys.push(keyInfo);
      }
    }
    return keys;
  }

  async getKeyStatistics() {
    const stats = {
      totalKeys: this.activeKeys.size,
      activeKeys: 0,
      expiredKeys: 0,
      rotationQueue: this.rotationQueue.length,
      keyTypes: {},
      recentRotations: [],
      upcomingRotations: []
    };
    
    const now = Date.now();
    
    for (const [keyId, keyInfo] of this.activeKeys) {
      if (keyInfo.isActive) {
        stats.activeKeys++;
        
        if (!stats.keyTypes[keyInfo.type]) {
          stats.keyTypes[keyInfo.type] = 0;
        }
        stats.keyTypes[keyInfo.type]++;
      } else {
        stats.expiredKeys++;
      }
    }
    
    // Get upcoming rotations
    const sortedQueue = [...this.rotationQueue].sort((a, b) => a.scheduledTime - b.scheduledTime);
    stats.upcomingRotations = sortedQueue.slice(0, 5).map(item => ({
      keyId: item.keyId,
      keyType: item.keyType,
      scheduledTime: new Date(item.scheduledTime).toISOString(),
      priority: item.priority
    }));
    
    return stats;
  }

  async shutdown() {
    try {
      this.logger.info('Shutting down Key Management System...');
      
      // Clear monitoring intervals
      for (const [name, interval] of this.monitoringIntervals) {
        clearInterval(interval);
      }
      
      // Flush cache
      this.keyCache.flushAll();
      this.rotationCache.flushAll();
      
      this.isActive = false;
      this.logger.info('Key Management System shut down successfully');
      
    } catch (error) {
      this.logger.error('Error shutting down Key Management System:', error);
    }
  }
}

module.exports = KeyManagementSystem;
