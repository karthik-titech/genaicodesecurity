const crypto = require('crypto');
const NodeCache = require('node-cache');
const Logger = require('../utils/Logger');

class WorkflowHandleRotation {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Handle storage and cache
    this.handleCache = new NodeCache({
      stdTTL: 1800, // 30 minutes default TTL
      checkperiod: 300
    });
    
    // Active handles registry
    this.activeHandles = new Map();
    
    // Handle rotation queue
    this.rotationQueue = [];
    
    // Handle types and their configurations
    this.handleTypes = {
      session: {
        algorithm: 'sha256',
        handleLength: 32,
        rotationInterval: 60 * 60 * 1000, // 1 hour
        warningThreshold: 10 * 60 * 1000, // 10 minutes
        maxLifetime: 24 * 60 * 60 * 1000, // 24 hours
        maxUsage: 1000
      },
      workflow: {
        algorithm: 'sha512',
        handleLength: 64,
        rotationInterval: 30 * 60 * 1000, // 30 minutes
        warningThreshold: 5 * 60 * 1000, // 5 minutes
        maxLifetime: 4 * 60 * 60 * 1000, // 4 hours
        maxUsage: 100
      },
      api: {
        algorithm: 'sha256',
        handleLength: 48,
        rotationInterval: 15 * 60 * 1000, // 15 minutes
        warningThreshold: 2 * 60 * 1000, // 2 minutes
        maxLifetime: 60 * 60 * 1000, // 1 hour
        maxUsage: 500
      },
      device: {
        algorithm: 'sha384',
        handleLength: 56,
        rotationInterval: 5 * 60 * 1000, // 5 minutes
        warningThreshold: 1 * 60 * 1000, // 1 minute
        maxLifetime: 30 * 60 * 1000, // 30 minutes
        maxUsage: 50
      }
    };
    
    // Handle usage patterns
    this.usagePatterns = new Map();
    
    // Monitoring intervals
    this.monitoringIntervals = new Map();
    
    // Handle security policies
    this.securityPolicies = {
      preventReuse: true,
      enforceRotation: true,
      trackUsage: true,
      anomalyDetection: true,
      rateLimitPerHandle: 100,
      maxConcurrentHandles: 1000
    };
  }

  async initialize() {
    try {
      this.logger.info('Initializing Workflow Handle Rotation System...');
      
      // Set up cache event listeners
      this.setupCacheListeners();
      
      // Start handle monitoring
      this.startHandleMonitoring();
      
      // Initialize rotation scheduler
      this.initializeRotationScheduler();
      
      this.isActive = true;
      this.logger.info('Workflow Handle Rotation System initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Workflow Handle Rotation System:', error);
      throw error;
    }
  }

  async generateHandle(handleType, context = {}) {
    try {
      const config = this.handleTypes[handleType];
      if (!config) {
        throw new Error(`Unknown handle type: ${handleType}`);
      }
      
      const handleId = this.generateHandleId(handleType);
      const handleData = await this.createHandle(handleType, config);
      
      const handleInfo = {
        id: handleId,
        type: handleType,
        algorithm: config.algorithm,
        handleLength: config.handleLength,
        createdAt: Date.now(),
        expiresAt: Date.now() + config.maxLifetime,
        rotationInterval: config.rotationInterval,
        warningThreshold: config.warningThreshold,
        maxLifetime: config.maxLifetime,
        maxUsage: config.maxUsage,
        isActive: true,
        usageCount: 0,
        lastUsed: null,
        context: context,
        metadata: {
          ip: context.ip,
          userAgent: context.userAgent,
          userId: context.userId,
          sessionId: context.sessionId
        }
      };
      
      // Add to active handles
      this.activeHandles.set(handleId, handleInfo);
      this.handleCache.set(handleId, handleInfo);
      
      // Schedule rotation
      this.scheduleHandleRotation(handleId, handleInfo);
      
      // Track usage pattern
      this.trackUsagePattern(handleId, handleInfo);
      
      this.logger.info(`Generated new ${handleType} handle: ${handleId}`);
      
      return {
        handleId,
        handleData,
        handleInfo
      };
      
    } catch (error) {
      this.logger.error(`Error generating ${handleType} handle:`, error);
      throw error;
    }
  }

  async createHandle(handleType, config) {
    const randomBytes = crypto.randomBytes(config.handleLength);
    
    switch (handleType) {
      case 'session':
        return crypto.createHash(config.algorithm).update(randomBytes).digest('hex');
        
      case 'workflow':
        return crypto.createHash(config.algorithm).update(randomBytes).digest('hex');
        
      case 'api':
        return crypto.createHash(config.algorithm).update(randomBytes).digest('hex');
        
      case 'device':
        return crypto.createHash(config.algorithm).update(randomBytes).digest('hex');
        
      default:
        throw new Error(`Unsupported handle type: ${handleType}`);
    }
  }

  async validateHandle(handleId, context = {}) {
    try {
      // Check cache first
      let handleInfo = this.handleCache.get(handleId);
      
      if (!handleInfo) {
        handleInfo = this.activeHandles.get(handleId);
        if (handleInfo) {
          this.handleCache.set(handleId, handleInfo);
        }
      }
      
      if (!handleInfo || !handleInfo.isActive) {
        throw new Error(`Handle not found or inactive: ${handleId}`);
      }
      
      // Check if handle is expired
      if (this.isHandleExpired(handleInfo)) {
        await this.handleHandleExpiration(handleId);
        throw new Error(`Handle expired: ${handleId}`);
      }
      
      // Check usage limits
      if (handleInfo.usageCount >= handleInfo.maxUsage) {
        await this.handleHandleExhaustion(handleId);
        throw new Error(`Handle usage limit exceeded: ${handleId}`);
      }
      
      // Check for suspicious usage patterns
      if (this.securityPolicies.anomalyDetection) {
        const anomaly = this.detectAnomaly(handleId, handleInfo, context);
        if (anomaly) {
          this.logger.warn(`Anomaly detected for handle ${handleId}:`, anomaly);
          await this.handleAnomaly(handleId, anomaly);
        }
      }
      
      // Update usage statistics
      handleInfo.usageCount++;
      handleInfo.lastUsed = Date.now();
      
      // Check if rotation is needed
      if (this.shouldRotateHandle(handleInfo)) {
        await this.rotateHandle(handleId);
      }
      
      return {
        valid: true,
        handleInfo,
        remainingUsage: handleInfo.maxUsage - handleInfo.usageCount
      };
      
    } catch (error) {
      this.logger.error(`Error validating handle ${handleId}:`, error);
      return {
        valid: false,
        error: error.message
      };
    }
  }

  async rotateHandle(handleId) {
    try {
      const handleInfo = this.activeHandles.get(handleId);
      if (!handleInfo) {
        throw new Error(`Handle not found: ${handleId}`);
      }
      
      this.logger.info(`Starting handle rotation for: ${handleId}`);
      
      // Generate new handle
      const newHandle = await this.generateHandle(handleInfo.type, handleInfo.context);
      
      // Mark old handle for deprecation
      handleInfo.isActive = false;
      handleInfo.deprecatedAt = Date.now();
      handleInfo.replacedBy = newHandle.handleId;
      
      // Keep old handle for a grace period
      setTimeout(async () => {
        await this.removeHandle(handleId);
      }, 5 * 60 * 1000); // 5 minutes grace period
      
      this.logger.info(`Handle rotation completed: ${handleId} -> ${newHandle.handleId}`);
      
      return newHandle;
      
    } catch (error) {
      this.logger.error(`Error rotating handle ${handleId}:`, error);
      throw error;
    }
  }

  async handleHandleExpiration(handleId) {
    try {
      this.logger.warn(`Handling handle expiration: ${handleId}`);
      
      const handleInfo = this.activeHandles.get(handleId);
      if (!handleInfo) {
        return;
      }
      
      // Mark as expired
      handleInfo.isActive = false;
      handleInfo.expiredAt = Date.now();
      
      // Generate replacement handle
      await this.generateHandle(handleInfo.type, handleInfo.context);
      
      // Remove expired handle after grace period
      setTimeout(async () => {
        await this.removeHandle(handleId);
      }, 2 * 60 * 1000); // 2 minutes grace period
      
    } catch (error) {
      this.logger.error(`Error handling handle expiration for ${handleId}:`, error);
    }
  }

  async handleHandleExhaustion(handleId) {
    try {
      this.logger.warn(`Handling handle exhaustion: ${handleId}`);
      
      const handleInfo = this.activeHandles.get(handleId);
      if (!handleInfo) {
        return;
      }
      
      // Mark as exhausted
      handleInfo.isActive = false;
      handleInfo.exhaustedAt = Date.now();
      
      // Generate replacement handle
      await this.generateHandle(handleInfo.type, handleInfo.context);
      
      // Remove exhausted handle immediately
      await this.removeHandle(handleId);
      
    } catch (error) {
      this.logger.error(`Error handling handle exhaustion for ${handleId}:`, error);
    }
  }

  async handleAnomaly(handleId, anomaly) {
    try {
      this.logger.warn(`Handling anomaly for handle ${handleId}:`, anomaly);
      
      const handleInfo = this.activeHandles.get(handleId);
      if (!handleInfo) {
        return;
      }
      
      // Mark as suspicious
      handleInfo.isActive = false;
      handleInfo.suspiciousAt = Date.now();
      handleInfo.anomaly = anomaly;
      
      // Generate replacement handle with enhanced security
      await this.generateHandle(handleInfo.type, {
        ...handleInfo.context,
        enhancedSecurity: true,
        anomalyDetected: true
      });
      
      // Remove suspicious handle immediately
      await this.removeHandle(handleId);
      
    } catch (error) {
      this.logger.error(`Error handling anomaly for handle ${handleId}:`, error);
    }
  }

  async removeHandle(handleId) {
    try {
      // Remove from active handles
      this.activeHandles.delete(handleId);
      this.handleCache.del(handleId);
      
      // Remove usage pattern
      this.usagePatterns.delete(handleId);
      
      this.logger.info(`Removed handle: ${handleId}`);
      
    } catch (error) {
      this.logger.error(`Error removing handle ${handleId}:`, error);
    }
  }

  setupCacheListeners() {
    this.handleCache.on('expired', (key, value) => {
      this.logger.info(`Handle cache expired: ${key}`);
    });
  }

  startHandleMonitoring() {
    // Monitor handle expiration every 2 minutes
    this.monitoringIntervals.set('expiration', setInterval(() => {
      this.checkHandleExpiration();
    }, 2 * 60 * 1000));
    
    // Monitor handle rotation every 5 minutes
    this.monitoringIntervals.set('rotation', setInterval(() => {
      this.processRotationQueue();
    }, 5 * 60 * 1000));
    
    // Monitor handle health every 10 minutes
    this.monitoringIntervals.set('health', setInterval(() => {
      this.checkHandleHealth();
    }, 10 * 60 * 1000));
    
    // Monitor usage patterns every 15 minutes
    this.monitoringIntervals.set('usage', setInterval(() => {
      this.analyzeUsagePatterns();
    }, 15 * 60 * 1000));
  }

  async checkHandleExpiration() {
    try {
      const now = Date.now();
      
      for (const [handleId, handleInfo] of this.activeHandles) {
        if (handleInfo.expiresAt && now >= handleInfo.expiresAt) {
          await this.handleHandleExpiration(handleId);
        } else if (handleInfo.expiresAt && (handleInfo.expiresAt - now) <= handleInfo.warningThreshold) {
          this.logger.warn(`Handle ${handleId} will expire soon: ${new Date(handleInfo.expiresAt).toISOString()}`);
        }
      }
      
    } catch (error) {
      this.logger.error('Error checking handle expiration:', error);
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
      const handlesToRotate = this.rotationQueue.filter(item => item.scheduledTime <= now);
      
      for (const item of handlesToRotate) {
        try {
          await this.rotateHandle(item.handleId);
          this.rotationQueue = this.rotationQueue.filter(q => q.handleId !== item.handleId);
        } catch (error) {
          this.logger.error(`Failed to rotate handle ${item.handleId}:`, error);
        }
      }
      
    } catch (error) {
      this.logger.error('Error processing rotation queue:', error);
    }
  }

  async checkHandleHealth() {
    try {
      const healthReport = {
        totalHandles: this.activeHandles.size,
        activeHandles: 0,
        expiringHandles: 0,
        expiredHandles: 0,
        rotationQueue: this.rotationQueue.length,
        handleTypes: {}
      };
      
      const now = Date.now();
      
      for (const [handleId, handleInfo] of this.activeHandles) {
        if (handleInfo.isActive) {
          healthReport.activeHandles++;
          
          if (!healthReport.handleTypes[handleInfo.type]) {
            healthReport.handleTypes[handleInfo.type] = 0;
          }
          healthReport.handleTypes[handleInfo.type]++;
          
          if (handleInfo.expiresAt && (handleInfo.expiresAt - now) <= handleInfo.warningThreshold) {
            healthReport.expiringHandles++;
          }
        } else {
          healthReport.expiredHandles++;
        }
      }
      
      this.logger.info('Handle health report:', healthReport);
      
    } catch (error) {
      this.logger.error('Error checking handle health:', error);
    }
  }

  async analyzeUsagePatterns() {
    try {
      const patterns = {
        totalUsage: 0,
        averageUsagePerHandle: 0,
        highUsageHandles: [],
        suspiciousPatterns: []
      };
      
      for (const [handleId, handleInfo] of this.activeHandles) {
        patterns.totalUsage += handleInfo.usageCount;
        
        if (handleInfo.usageCount > handleInfo.maxUsage * 0.8) {
          patterns.highUsageHandles.push({
            handleId,
            type: handleInfo.type,
            usageCount: handleInfo.usageCount,
            maxUsage: handleInfo.maxUsage
          });
        }
      }
      
      patterns.averageUsagePerHandle = patterns.totalUsage / this.activeHandles.size;
      
      // Detect suspicious patterns
      for (const [handleId, pattern] of this.usagePatterns) {
        if (this.isSuspiciousPattern(pattern)) {
          patterns.suspiciousPatterns.push({
            handleId,
            pattern: pattern
          });
        }
      }
      
      this.logger.info('Usage patterns analysis:', patterns);
      
    } catch (error) {
      this.logger.error('Error analyzing usage patterns:', error);
    }
  }

  scheduleHandleRotation(handleId, handleInfo) {
    const rotationTime = handleInfo.createdAt + handleInfo.rotationInterval;
    const priority = this.getRotationPriority(handleInfo);
    
    this.rotationQueue.push({
      handleId,
      handleType: handleInfo.type,
      priority,
      scheduledTime: rotationTime
    });
  }

  getRotationPriority(handleInfo) {
    // Higher priority for handles that are expiring soon or have high usage
    const timeToExpiry = handleInfo.expiresAt - Date.now();
    const timeToRotation = (handleInfo.createdAt + handleInfo.rotationInterval) - Date.now();
    const usageRatio = handleInfo.usageCount / handleInfo.maxUsage;
    
    if (timeToExpiry < 5 * 60 * 1000) { // Less than 5 minutes
      return 10;
    } else if (usageRatio > 0.9) { // More than 90% usage
      return 9;
    } else if (timeToExpiry < 15 * 60 * 1000) { // Less than 15 minutes
      return 8;
    } else if (timeToRotation < 0) { // Overdue for rotation
      return 7;
    } else if (usageRatio > 0.7) { // More than 70% usage
      return 6;
    } else if (timeToRotation < 5 * 60 * 1000) { // Due within 5 minutes
      return 5;
    } else {
      return 3;
    }
  }

  trackUsagePattern(handleId, handleInfo) {
    const pattern = {
      handleId,
      type: handleInfo.type,
      usageHistory: [],
      lastAccess: null,
      accessFrequency: 0,
      suspiciousAccess: false
    };
    
    this.usagePatterns.set(handleId, pattern);
  }

  updateUsagePattern(handleId, context) {
    const pattern = this.usagePatterns.get(handleId);
    if (!pattern) {
      return;
    }
    
    const now = Date.now();
    
    pattern.usageHistory.push({
      timestamp: now,
      context: context
    });
    
    // Keep only last 100 usage records
    if (pattern.usageHistory.length > 100) {
      pattern.usageHistory = pattern.usageHistory.slice(-100);
    }
    
    pattern.lastAccess = now;
    
    // Calculate access frequency
    if (pattern.usageHistory.length > 1) {
      const timeSpan = now - pattern.usageHistory[0].timestamp;
      pattern.accessFrequency = pattern.usageHistory.length / (timeSpan / 1000); // accesses per second
    }
  }

  detectAnomaly(handleId, handleInfo, context) {
    const pattern = this.usagePatterns.get(handleId);
    if (!pattern) {
      return null;
    }
    
    const anomalies = [];
    
    // Check for rapid usage
    if (pattern.accessFrequency > 10) { // More than 10 accesses per second
      anomalies.push({
        type: 'rapid_usage',
        severity: 'high',
        details: `Access frequency: ${pattern.accessFrequency.toFixed(2)}/s`
      });
    }
    
    // Check for usage from multiple IPs
    const uniqueIPs = new Set(pattern.usageHistory.map(u => u.context.ip));
    if (uniqueIPs.size > 5) {
      anomalies.push({
        type: 'multiple_ips',
        severity: 'medium',
        details: `Used from ${uniqueIPs.size} different IPs`
      });
    }
    
    // Check for unusual time patterns
    const now = new Date();
    const hour = now.getHours();
    if (hour < 6 || hour > 22) { // Usage outside normal hours
      anomalies.push({
        type: 'unusual_hours',
        severity: 'low',
        details: `Usage at ${hour}:00`
      });
    }
    
    return anomalies.length > 0 ? anomalies : null;
  }

  isSuspiciousPattern(pattern) {
    return pattern.accessFrequency > 5 || // High frequency
           pattern.usageHistory.length > 50 || // High volume
           pattern.suspiciousAccess; // Flagged as suspicious
  }

  isHandleValid(handleInfo) {
    return handleInfo.isActive && 
           handleInfo.expiresAt > Date.now() &&
           handleInfo.usageCount < handleInfo.maxUsage;
  }

  isHandleExpired(handleInfo) {
    return !handleInfo.isActive || handleInfo.expiresAt <= Date.now();
  }

  shouldRotateHandle(handleInfo) {
    const now = Date.now();
    return (handleInfo.createdAt + handleInfo.rotationInterval) <= now ||
           handleInfo.usageCount >= handleInfo.maxUsage * 0.9;
  }

  generateHandleId(handleType) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    return `${handleType}_${timestamp}_${random}`;
  }

  getActiveHandlesByType(handleType) {
    const handles = [];
    for (const [handleId, handleInfo] of this.activeHandles) {
      if (handleInfo.type === handleType && handleInfo.isActive) {
        handles.push(handleInfo);
      }
    }
    return handles;
  }

  async getHandleStatistics() {
    const stats = {
      totalHandles: this.activeHandles.size,
      activeHandles: 0,
      expiredHandles: 0,
      rotationQueue: this.rotationQueue.length,
      handleTypes: {},
      usagePatterns: {},
      recentRotations: [],
      upcomingRotations: []
    };
    
    const now = Date.now();
    
    for (const [handleId, handleInfo] of this.activeHandles) {
      if (handleInfo.isActive) {
        stats.activeHandles++;
        
        if (!stats.handleTypes[handleInfo.type]) {
          stats.handleTypes[handleInfo.type] = 0;
        }
        stats.handleTypes[handleInfo.type]++;
        
        // Track usage patterns by type
        if (!stats.usagePatterns[handleInfo.type]) {
          stats.usagePatterns[handleInfo.type] = {
            totalUsage: 0,
            averageUsage: 0,
            maxUsage: 0
          };
        }
        stats.usagePatterns[handleInfo.type].totalUsage += handleInfo.usageCount;
        stats.usagePatterns[handleInfo.type].maxUsage = Math.max(
          stats.usagePatterns[handleInfo.type].maxUsage,
          handleInfo.usageCount
        );
      } else {
        stats.expiredHandles++;
      }
    }
    
    // Calculate averages
    for (const [type, pattern] of Object.entries(stats.usagePatterns)) {
      const typeCount = stats.handleTypes[type] || 0;
      pattern.averageUsage = typeCount > 0 ? pattern.totalUsage / typeCount : 0;
    }
    
    // Get upcoming rotations
    const sortedQueue = [...this.rotationQueue].sort((a, b) => a.scheduledTime - b.scheduledTime);
    stats.upcomingRotations = sortedQueue.slice(0, 10).map(item => ({
      handleId: item.handleId,
      handleType: item.handleType,
      scheduledTime: new Date(item.scheduledTime).toISOString(),
      priority: item.priority
    }));
    
    return stats;
  }

  async shutdown() {
    try {
      this.logger.info('Shutting down Workflow Handle Rotation System...');
      
      // Clear monitoring intervals
      for (const [name, interval] of this.monitoringIntervals) {
        clearInterval(interval);
      }
      
      // Flush cache
      this.handleCache.flushAll();
      
      this.isActive = false;
      this.logger.info('Workflow Handle Rotation System shut down successfully');
      
    } catch (error) {
      this.logger.error('Error shutting down Workflow Handle Rotation System:', error);
    }
  }
}

module.exports = WorkflowHandleRotation;
