const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Logger = require('../utils/Logger');

class ConfigManager {
  constructor() {
    this.logger = new Logger();
    this.config = {};
    this.encryptedKeys = {};
    this.isInitialized = false;
    
    // Configuration file paths
    this.configPath = path.join(__dirname, '../../config');
    this.secretsPath = path.join(__dirname, '../../config/secrets.json');
    this.encryptedSecretsPath = path.join(__dirname, '../../config/secrets.encrypted');
    
    // Encryption settings
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
    this.tagLength = 16;
  }

  async initialize() {
    try {
      this.logger.info('Initializing Config Manager...');
      
      // Create config directory if it doesn't exist
      if (!fs.existsSync(this.configPath)) {
        fs.mkdirSync(this.configPath, { recursive: true });
        this.logger.info('Created config directory');
      }
      
      // Load environment variables
      this.loadEnvironmentConfig();
      
      // Load encrypted secrets if they exist
      await this.loadEncryptedSecrets();
      
      // Validate configuration
      this.validateConfiguration();
      
      this.isInitialized = true;
      this.logger.info('Config Manager initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Config Manager:', error);
      throw error;
    }
  }

  loadEnvironmentConfig() {
    // Load configuration from environment variables
    this.config = {
      // Server Configuration
      port: process.env.PORT || 3000,
      nodeEnv: process.env.NODE_ENV || 'development',
      
      // Security Configuration
      strictMode: process.env.STRICT_MODE === 'true',
      maxContextSize: parseInt(process.env.MAX_CONTEXT_SIZE) || 10000,
      maxToolChaining: parseInt(process.env.MAX_TOOL_CHAINING) || 3,
      
      // Logging Configuration
      logLevel: process.env.LOG_LEVEL || 'info',
      
      // CORS Configuration
      allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      
      // Cache Configuration
      redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
      
      // Security Thresholds
      threatThresholds: {
        low: parseFloat(process.env.THREAT_THRESHOLD_LOW) || 0.1,
        medium: parseFloat(process.env.THREAT_THRESHOLD_MEDIUM) || 0.3,
        high: parseFloat(process.env.THREAT_THRESHOLD_HIGH) || 0.6,
        critical: parseFloat(process.env.THREAT_THRESHOLD_CRITICAL) || 0.8
      },
      
      // Rate Limiting
      rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
      },
      
      // Session Configuration
      session: {
        ttl: parseInt(process.env.SESSION_TTL) || 3600,
        confirmationTtl: parseInt(process.env.CONFIRMATION_TTL) || 300
      },
      
      // Database Configuration
      database: {
        url: process.env.DATABASE_URL || 'sqlite:./security_patch.db'
      },
      
      // Monitoring and Alerting
      monitoring: {
        alertWebhookUrl: process.env.ALERT_WEBHOOK_URL,
        securityEmail: process.env.SECURITY_EMAIL
      },
      
      // Development Settings
      development: {
        debug: process.env.DEBUG === 'true',
        enableTestEndpoints: process.env.ENABLE_TEST_ENDPOINTS === 'true'
      }
    };
  }

  async loadEncryptedSecrets() {
    try {
      if (fs.existsSync(this.encryptedSecretsPath)) {
        const encryptedData = fs.readFileSync(this.encryptedSecretsPath, 'utf8');
        const decryptedData = await this.decryptSecrets(encryptedData);
        this.encryptedKeys = JSON.parse(decryptedData);
        this.logger.info('Loaded encrypted secrets');
      } else {
        // Create initial secrets file if it doesn't exist
        await this.createInitialSecrets();
      }
    } catch (error) {
      this.logger.error('Error loading encrypted secrets:', error);
      throw error;
    }
  }

  async createInitialSecrets() {
    const initialSecrets = {
      googleHome: {
        apiKey: process.env.GOOGLE_HOME_API_KEY || '',
        webhookSecret: process.env.GOOGLE_HOME_WEBHOOK_SECRET || this.generateSecureSecret(32)
      },
      calendar: {
        apiKey: process.env.GOOGLE_CALENDAR_API_KEY || '',
        webhookSecret: process.env.CALENDAR_WEBHOOK_SECRET || this.generateSecureSecret(32)
      },
      jwt: {
        secret: process.env.JWT_SECRET || this.generateSecureSecret(64),
        refreshSecret: process.env.JWT_REFRESH_SECRET || this.generateSecureSecret(64)
      },
      apiKeys: {
        // Generate default API keys for different tiers
        free: process.env.FREE_TIER_API_KEY || this.generateSecureSecret(32),
        pro: process.env.PRO_TIER_API_KEY || this.generateSecureSecret(32),
        enterprise: process.env.ENTERPRISE_API_KEY || this.generateSecureSecret(32)
      },
      encryption: {
        masterKey: this.generateMasterKey()
      }
    };

    await this.saveEncryptedSecrets(initialSecrets);
    this.encryptedKeys = initialSecrets;
    this.logger.info('Created initial encrypted secrets file');
  }

  generateSecureSecret(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Enhanced API key management
  async generateAPIKey(tier = 'free', userId = null) {
    const apiKey = this.generateSecureSecret(32);
    const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    
    const keyData = {
      key: apiKeyHash,
      tier,
      userId,
      createdAt: new Date().toISOString(),
      lastUsed: null,
      isActive: true
    };

    // Store API key hash in encrypted secrets
    if (!this.encryptedKeys.apiKeyHashes) {
      this.encryptedKeys.apiKeyHashes = {};
    }
    
    this.encryptedKeys.apiKeyHashes[apiKeyHash] = keyData;
    await this.saveEncryptedSecrets(this.encryptedKeys);
    
    this.logger.info(`Generated new API key for tier: ${tier}, userId: ${userId}`);
    
    // Return the plain API key (only time it's exposed)
    return {
      apiKey,
      tier,
      userId,
      createdAt: keyData.createdAt
    };
  }

  async validateAPIKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
      return { valid: false, reason: 'Invalid API key format' };
    }

    const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const keyData = this.encryptedKeys.apiKeyHashes?.[apiKeyHash];
    
    if (!keyData) {
      return { valid: false, reason: 'API key not found' };
    }

    if (!keyData.isActive) {
      return { valid: false, reason: 'API key is inactive' };
    }

    // Update last used timestamp
    keyData.lastUsed = new Date().toISOString();
    this.encryptedKeys.apiKeyHashes[apiKeyHash] = keyData;
    await this.saveEncryptedSecrets(this.encryptedKeys);

    return {
      valid: true,
      tier: keyData.tier,
      userId: keyData.userId,
      createdAt: keyData.createdAt
    };
  }

  async revokeAPIKey(apiKeyHash) {
    if (this.encryptedKeys.apiKeyHashes?.[apiKeyHash]) {
      this.encryptedKeys.apiKeyHashes[apiKeyHash].isActive = false;
      this.encryptedKeys.apiKeyHashes[apiKeyHash].revokedAt = new Date().toISOString();
      await this.saveEncryptedSecrets(this.encryptedKeys);
      this.logger.info(`Revoked API key: ${apiKeyHash.substring(0, 8)}...`);
      return true;
    }
    return false;
  }

  async listAPIKeys() {
    const keys = [];
    if (this.encryptedKeys.apiKeyHashes) {
      for (const [hash, data] of Object.entries(this.encryptedKeys.apiKeyHashes)) {
        keys.push({
          hash: hash.substring(0, 8) + '...',
          tier: data.tier,
          userId: data.userId,
          createdAt: data.createdAt,
          lastUsed: data.lastUsed,
          isActive: data.isActive,
          revokedAt: data.revokedAt
        });
      }
    }
    return keys;
  }

  async saveEncryptedSecrets(secrets) {
    try {
      const encryptedData = await this.encryptSecrets(JSON.stringify(secrets));
      fs.writeFileSync(this.encryptedSecretsPath, encryptedData);
      this.logger.info('Saved encrypted secrets');
    } catch (error) {
      this.logger.error('Error saving encrypted secrets:', error);
      throw error;
    }
  }

  async encryptSecrets(data) {
    const key = this.getEncryptionKey();
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipher(this.algorithm, key);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      encrypted: encrypted,
      tag: tag.toString('hex')
    });
  }

  async decryptSecrets(encryptedData) {
    const key = this.getEncryptionKey();
    const data = JSON.parse(encryptedData);
    
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
    
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  getEncryptionKey() {
    // Use environment variable for encryption key, or generate one
    const envKey = process.env.ENCRYPTION_KEY;
    if (envKey) {
      return crypto.scryptSync(envKey, 'salt', this.keyLength);
    }
    
    // Fallback to master key from encrypted secrets
    if (this.encryptedKeys.encryption?.masterKey) {
      return crypto.scryptSync(this.encryptedKeys.encryption.masterKey, 'salt', this.keyLength);
    }
    
    // Generate new key if none exists
    const newKey = this.generateMasterKey();
    return crypto.scryptSync(newKey, 'salt', this.keyLength);
  }

  generateMasterKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  validateConfiguration() {
    const requiredConfigs = [
      'port',
      'nodeEnv',
      'maxContextSize',
      'maxToolChaining',
      'logLevel'
    ];

    const missingConfigs = requiredConfigs.filter(config => !this.config[config]);
    
    if (missingConfigs.length > 0) {
      throw new Error(`Missing required configuration: ${missingConfigs.join(', ')}`);
    }

    // Validate API keys if they exist
    if (this.encryptedKeys.googleHome?.apiKey && !this.encryptedKeys.googleHome.apiKey.startsWith('AIza')) {
      this.logger.warn('Google Home API key format appears invalid');
    }

    if (this.encryptedKeys.calendar?.apiKey && !this.encryptedKeys.calendar.apiKey.startsWith('AIza')) {
      this.logger.warn('Google Calendar API key format appears invalid');
    }
  }

  getConfig(key) {
    if (!this.isInitialized) {
      throw new Error('Config Manager not initialized');
    }
    return this.config[key];
  }

  getSecret(key) {
    if (!this.isInitialized) {
      throw new Error('Config Manager not initialized');
    }
    
    // Access encrypted secrets securely
    const secretPath = key.split('.');
    let secret = this.encryptedKeys;
    
    for (const path of secretPath) {
      if (secret && typeof secret === 'object' && secret[path]) {
        secret = secret[path];
      } else {
        return null;
      }
    }
    
    return secret;
  }

  async updateSecret(key, value) {
    if (!this.isInitialized) {
      throw new Error('Config Manager not initialized');
    }

    const secretPath = key.split('.');
    let current = this.encryptedKeys;
    
    // Navigate to the parent of the target key
    for (let i = 0; i < secretPath.length - 1; i++) {
      if (!current[secretPath[i]]) {
        current[secretPath[i]] = {};
      }
      current = current[secretPath[i]];
    }
    
    // Set the value
    current[secretPath[secretPath.length - 1]] = value;
    
    // Save encrypted secrets
    await this.saveEncryptedSecrets(this.encryptedKeys);
    
    this.logger.info(`Updated secret: ${key}`);
  }

  async updateConfig(key, value) {
    if (!this.isInitialized) {
      throw new Error('Config Manager not initialized');
    }

    this.config[key] = value;
    this.logger.info(`Updated config: ${key}`);
  }

  getFullConfig() {
    if (!this.isInitialized) {
      throw new Error('Config Manager not initialized');
    }

    return {
      config: this.config,
      secrets: this.getSecretsSummary()
    };
  }

  getSecretsSummary() {
    // Return a summary of secrets without exposing actual values
    const summary = {};
    
    if (this.encryptedKeys.googleHome) {
      summary.googleHome = {
        apiKey: this.encryptedKeys.googleHome.apiKey ? '[SET]' : '[NOT SET]',
        projectId: this.encryptedKeys.googleHome.projectId ? '[SET]' : '[NOT SET]'
      };
    }
    
    if (this.encryptedKeys.calendar) {
      summary.calendar = {
        apiKey: this.encryptedKeys.calendar.apiKey ? '[SET]' : '[NOT SET]',
        webhookSecret: this.encryptedKeys.calendar.webhookSecret ? '[SET]' : '[NOT SET]'
      };
    }
    
    return summary;
  }

  isInitialized() {
    return this.isInitialized;
  }

  // Utility method to check if secrets are properly configured
  validateSecrets() {
    const validation = {
      valid: true,
      issues: []
    };

    if (!this.encryptedKeys.googleHome?.apiKey) {
      validation.issues.push('Google Home API key not configured');
      validation.valid = false;
    }

    if (!this.encryptedKeys.calendar?.apiKey) {
      validation.issues.push('Google Calendar API key not configured');
      validation.valid = false;
    }

    return validation;
  }
}

module.exports = ConfigManager;
