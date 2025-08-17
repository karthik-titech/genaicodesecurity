const NodeCache = require('node-cache');
const bcrypt = require('bcryptjs');
const Logger = require('../utils/Logger');

class AccessControlManager {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Access control cache
    this.accessCache = new NodeCache({
      stdTTL: 1800, // 30 minutes default TTL
      checkperiod: 300
    });
    
    // User permissions cache
    this.permissionsCache = new NodeCache({
      stdTTL: 3600, // 1 hour default TTL
      checkperiod: 600
    });
    
    // Device access cache
    this.deviceCache = new NodeCache({
      stdTTL: 7200, // 2 hours default TTL
      checkperiod: 600
    });
    
    // Permission levels
    this.permissionLevels = {
      NONE: 0,
      READ: 1,
      WRITE: 2,
      ADMIN: 3,
      OWNER: 4
    };
    
    // Resource types
    this.resourceTypes = [
      'device',
      'calendar',
      'email',
      'file',
      'camera',
      'location',
      'contact',
      'payment',
      'app',
      'url'
    ];
    
    // Default permissions (most restrictive)
    this.defaultPermissions = {
      device: this.permissionLevels.READ,
      calendar: this.permissionLevels.READ,
      email: this.permissionLevels.NONE,
      file: this.permissionLevels.NONE,
      camera: this.permissionLevels.NONE,
      location: this.permissionLevels.NONE,
      contact: this.permissionLevels.NONE,
      payment: this.permissionLevels.NONE,
      app: this.permissionLevels.NONE,
      url: this.permissionLevels.NONE
    };
    
    // High-risk operations
    this.highRiskOperations = [
      'unlock_door',
      'open_window',
      'turn_on_boiler',
      'send_email',
      'delete_calendar',
      'access_camera',
      'share_location',
      'install_app',
      'make_payment',
      'transfer_money',
      'access_file',
      'open_url'
    ];
  }

  async initialize() {
    try {
      this.logger.info('Initializing Access Control Manager...');
      
      // Set up cache event listeners
      this.accessCache.on('expired', (key, value) => {
        this.logger.info(`Access control expired: ${key}`);
      });
      
      this.permissionsCache.on('expired', (key, value) => {
        this.logger.info(`Permissions expired: ${key}`);
      });
      
      this.deviceCache.on('expired', (key, value) => {
        this.logger.info(`Device access expired: ${key}`);
      });
      
      this.isActive = true;
      this.logger.info('Access Control Manager initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Access Control Manager:', error);
      throw error;
    }
  }

  async checkAccess(securityContext) {
    if (!this.isActive) {
      throw new Error('Access Control Manager not initialized');
    }

    const accessCheckResult = {
      allowed: false,
      reason: null,
      permissions: {},
      warnings: []
    };

    try {
      const userId = securityContext.userId;
      const sessionId = securityContext.sessionId;
      const source = securityContext.source;

      // Check if user exists and is authenticated
      const userCheck = await this.validateUser(userId);
      if (!userCheck.valid) {
        accessCheckResult.reason = userCheck.reason;
        return accessCheckResult;
      }

      // Check session validity
      const sessionCheck = await this.validateSession(sessionId, userId);
      if (!sessionCheck.valid) {
        accessCheckResult.reason = sessionCheck.reason;
        return accessCheckResult;
      }

      // Get user permissions
      const userPermissions = await this.getUserPermissions(userId);
      accessCheckResult.permissions = userPermissions;

      // Check source-specific access
      const sourceCheck = await this.checkSourceAccess(source, userPermissions);
      if (!sourceCheck.allowed) {
        accessCheckResult.reason = sourceCheck.reason;
        accessCheckResult.warnings.push(sourceCheck.warning);
        return accessCheckResult;
      }

      // Check for high-risk operations in input
      const riskCheck = await this.checkHighRiskOperations(securityContext.sanitizedInput, userPermissions);
      if (!riskCheck.allowed) {
        accessCheckResult.reason = riskCheck.reason;
        accessCheckResult.warnings.push(riskCheck.warning);
        return accessCheckResult;
      }

      // Check rate limits
      const rateCheck = await this.checkRateLimits(userId, sessionId);
      if (!rateCheck.allowed) {
        accessCheckResult.reason = rateCheck.reason;
        accessCheckResult.warnings.push(rateCheck.warning);
        return accessCheckResult;
      }

      accessCheckResult.allowed = true;
      
      this.logger.info('Access granted', {
        userId,
        sessionId,
        source,
        permissions: Object.keys(userPermissions)
      });

      return accessCheckResult;

    } catch (error) {
      this.logger.error('Error checking access:', error);
      accessCheckResult.reason = 'Access check error';
      return accessCheckResult;
    }
  }

  async validateUser(userId) {
    if (!userId) {
      return { valid: false, reason: 'No user ID provided' };
    }

    // Check if user exists in cache
    const userData = this.permissionsCache.get(`user_${userId}`);
    if (userData) {
      return { valid: true, userData };
    }

    // In a real implementation, this would check against a user database
    // For now, assume all users are valid
    const userData = {
      userId,
      status: 'active',
      permissions: this.defaultPermissions,
      createdAt: new Date().toISOString()
    };

    this.permissionsCache.set(`user_${userId}`, userData);
    return { valid: true, userData };
  }

  async validateSession(sessionId, userId) {
    if (!sessionId) {
      return { valid: false, reason: 'No session ID provided' };
    }

    // Check if session exists and is valid
    const sessionData = this.accessCache.get(`session_${sessionId}`);
    if (!sessionData) {
      return { valid: false, reason: 'Invalid session' };
    }

    if (sessionData.userId !== userId) {
      return { valid: false, reason: 'Session user mismatch' };
    }

    if (new Date() > new Date(sessionData.expiresAt)) {
      return { valid: false, reason: 'Session expired' };
    }

    return { valid: true, sessionData };
  }

  async getUserPermissions(userId) {
    const userData = this.permissionsCache.get(`user_${userId}`);
    if (userData) {
      return userData.permissions;
    }

    // Return default permissions
    return this.defaultPermissions;
  }

  async checkSourceAccess(source, userPermissions) {
    // Check if user has permission to access this source
    const sourcePermissions = {
      'google_home': userPermissions.device,
      'calendar': userPermissions.calendar,
      'email': userPermissions.email,
      'file': userPermissions.file,
      'camera': userPermissions.camera,
      'location': userPermissions.location,
      'contact': userPermissions.contact,
      'payment': userPermissions.payment,
      'app': userPermissions.app,
      'url': userPermissions.url
    };

    const permission = sourcePermissions[source] || this.permissionLevels.NONE;

    if (permission === this.permissionLevels.NONE) {
      return {
        allowed: false,
        reason: `No permission to access ${source}`,
        warning: `Access denied to ${source}`
      };
    }

    return { allowed: true };
  }

  async checkHighRiskOperations(input, userPermissions) {
    const detectedOperations = [];

    // Check for high-risk operations in input
    this.highRiskOperations.forEach(operation => {
      const pattern = new RegExp(`\\b${operation.replace(/_/g, '\\s*')}\\b`, 'i');
      if (pattern.test(input)) {
        detectedOperations.push(operation);
      }
    });

    if (detectedOperations.length === 0) {
      return { allowed: true };
    }

    // Check if user has sufficient permissions for high-risk operations
    for (const operation of detectedOperations) {
      const requiredPermission = this.getRequiredPermissionForOperation(operation);
      const userPermission = this.getUserPermissionForOperation(operation, userPermissions);

      if (userPermission < requiredPermission) {
        return {
          allowed: false,
          reason: `Insufficient permissions for ${operation}`,
          warning: `High-risk operation ${operation} requires ${this.getPermissionLevelName(requiredPermission)}`
        };
      }
    }

    return { allowed: true };
  }

  async checkRateLimits(userId, sessionId) {
    const now = Date.now();
    const minuteKey = `rate_${userId}_${Math.floor(now / 60000)}`;
    const sessionKey = `session_rate_${sessionId}`;

    // Check per-minute limit
    const minuteCount = this.accessCache.get(minuteKey) || 0;
    if (minuteCount >= 100) { // 100 requests per minute
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        warning: 'Too many requests per minute'
      };
    }

    // Check per-session limit
    const sessionCount = this.accessCache.get(sessionKey) || 0;
    if (sessionCount >= 1000) { // 1000 requests per session
      return {
        allowed: false,
        reason: 'Session rate limit exceeded',
        warning: 'Too many requests in this session'
      };
    }

    // Update counters
    this.accessCache.set(minuteKey, minuteCount + 1, 60);
    this.accessCache.set(sessionKey, sessionCount + 1, 3600);

    return { allowed: true };
  }

  getRequiredPermissionForOperation(operation) {
    const permissionMap = {
      'unlock_door': this.permissionLevels.ADMIN,
      'open_window': this.permissionLevels.ADMIN,
      'turn_on_boiler': this.permissionLevels.ADMIN,
      'send_email': this.permissionLevels.WRITE,
      'delete_calendar': this.permissionLevels.WRITE,
      'access_camera': this.permissionLevels.ADMIN,
      'share_location': this.permissionLevels.WRITE,
      'install_app': this.permissionLevels.ADMIN,
      'make_payment': this.permissionLevels.OWNER,
      'transfer_money': this.permissionLevels.OWNER,
      'access_file': this.permissionLevels.WRITE,
      'open_url': this.permissionLevels.READ
    };

    return permissionMap[operation] || this.permissionLevels.ADMIN;
  }

  getUserPermissionForOperation(operation, userPermissions) {
    // Map operations to resource types
    const operationMap = {
      'unlock_door': 'device',
      'open_window': 'device',
      'turn_on_boiler': 'device',
      'send_email': 'email',
      'delete_calendar': 'calendar',
      'access_camera': 'camera',
      'share_location': 'location',
      'install_app': 'app',
      'make_payment': 'payment',
      'transfer_money': 'payment',
      'access_file': 'file',
      'open_url': 'url'
    };

    const resourceType = operationMap[operation];
    return userPermissions[resourceType] || this.permissionLevels.NONE;
  }

  getPermissionLevelName(level) {
    const names = {
      [this.permissionLevels.NONE]: 'No Access',
      [this.permissionLevels.READ]: 'Read Only',
      [this.permissionLevels.WRITE]: 'Read/Write',
      [this.permissionLevels.ADMIN]: 'Administrator',
      [this.permissionLevels.OWNER]: 'Owner'
    };

    return names[level] || 'Unknown';
  }

  async grantPermission(userId, resourceType, permissionLevel) {
    if (!this.isActive) {
      throw new Error('Access Control Manager not initialized');
    }

    const userData = this.permissionsCache.get(`user_${userId}`);
    if (!userData) {
      throw new Error('User not found');
    }

    if (!this.resourceTypes.includes(resourceType)) {
      throw new Error('Invalid resource type');
    }

    if (!Object.values(this.permissionLevels).includes(permissionLevel)) {
      throw new Error('Invalid permission level');
    }

    // Update user permissions
    userData.permissions[resourceType] = permissionLevel;
    userData.updatedAt = new Date().toISOString();

    this.permissionsCache.set(`user_${userId}`, userData);

    this.logger.info('Permission granted', {
      userId,
      resourceType,
      permissionLevel: this.getPermissionLevelName(permissionLevel)
    });

    return { success: true, userData };
  }

  async revokePermission(userId, resourceType) {
    if (!this.isActive) {
      throw new Error('Access Control Manager not initialized');
    }

    const userData = this.permissionsCache.get(`user_${userId}`);
    if (!userData) {
      throw new Error('User not found');
    }

    // Revoke permission (set to NONE)
    userData.permissions[resourceType] = this.permissionLevels.NONE;
    userData.updatedAt = new Date().toISOString();

    this.permissionsCache.set(`user_${userId}`, userData);

    this.logger.info('Permission revoked', {
      userId,
      resourceType
    });

    return { success: true, userData };
  }

  async createSession(userId, sessionId, expiresIn = 3600) {
    if (!this.isActive) {
      throw new Error('Access Control Manager not initialized');
    }

    const sessionData = {
      sessionId,
      userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      permissions: await this.getUserPermissions(userId)
    };

    this.accessCache.set(`session_${sessionId}`, sessionData, expiresIn);

    this.logger.info('Session created', {
      sessionId,
      userId,
      expiresIn
    });

    return { success: true, sessionData };
  }

  async invalidateSession(sessionId) {
    if (!this.isActive) {
      throw new Error('Access Control Manager not initialized');
    }

    this.accessCache.del(`session_${sessionId}`);

    this.logger.info('Session invalidated', { sessionId });

    return { success: true };
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  getAccessControlStats() {
    return {
      active: this.isActive,
      accessCacheSize: this.accessCache.keys().length,
      permissionsCacheSize: this.permissionsCache.keys().length,
      deviceCacheSize: this.deviceCache.keys().length,
      permissionLevels: Object.keys(this.permissionLevels).length,
      resourceTypes: this.resourceTypes.length,
      highRiskOperations: this.highRiskOperations.length,
      defaultPermissions: Object.keys(this.defaultPermissions).length
    };
  }
}

module.exports = AccessControlManager;
