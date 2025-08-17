const NodeCache = require('node-cache');
const crypto = require('crypto');
const Logger = require('../utils/Logger');

class UserConfirmationSystem {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Confirmation cache with TTL
    this.confirmationCache = new NodeCache({
      stdTTL: 300, // 5 minutes default TTL
      checkperiod: 60 // Check every minute
    });
    
    // Pending confirmations cache
    this.pendingCache = new NodeCache({
      stdTTL: 600, // 10 minutes default TTL
      checkperiod: 60
    });
    
    // Actions that require confirmation
    this.confirmationRequiredActions = [
      'device_control',
      'data_exfiltration',
      'external_requests',
      'file_access',
      'camera_access',
      'location_access',
      'contact_access',
      'calendar_modification',
      'email_send',
      'smart_lock_control',
      'thermostat_control',
      'light_control',
      'app_installation',
      'url_open',
      'payment_processing'
    ];
    
    // High-risk patterns that trigger confirmation
    this.highRiskPatterns = [
      /unlock\s+door/i,
      /open\s+window/i,
      /turn\s+on\s+boiler/i,
      /send\s+email/i,
      /delete\s+calendar/i,
      /access\s+camera/i,
      /share\s+location/i,
      /install\s+app/i,
      /make\s+payment/i,
      /transfer\s+money/i
    ];
    
    // Confirmation methods
    this.confirmationMethods = [
      'voice_verification',
      'mobile_app',
      'email_verification',
      'sms_verification',
      'biometric_verification',
      'physical_button'
    ];
  }

  async initialize() {
    try {
      this.logger.info('Initializing User Confirmation System...');
      
      // Set up cache event listeners
      this.confirmationCache.on('expired', (key, value) => {
        this.logger.info(`Confirmation expired: ${key}`);
      });
      
      this.pendingCache.on('expired', (key, value) => {
        this.logger.warn(`Pending confirmation expired: ${key}`);
      });
      
      this.isActive = true;
      this.logger.info('User Confirmation System initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize User Confirmation System:', error);
      throw error;
    }
  }

  async createConfirmation(securityContext) {
    if (!this.isActive) {
      throw new Error('User Confirmation System not initialized');
    }

    const confirmationId = this.generateConfirmationId();
    const timestamp = new Date().toISOString();
    
    const confirmationData = {
      id: confirmationId,
      sessionId: securityContext.sessionId,
      userId: securityContext.userId,
      action: securityContext.confirmationReason || 'unknown_action',
      timestamp: timestamp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 minutes
      status: 'pending',
      method: this.determineConfirmationMethod(securityContext),
      context: {
        source: securityContext.source,
        threats: securityContext.threats,
        sanitizedInput: securityContext.sanitizedInput
      },
      attempts: 0,
      maxAttempts: 3
    };
    
    // Store confirmation data
    this.pendingCache.set(confirmationId, confirmationData);
    
    // Log confirmation creation
    this.logger.info('Confirmation created', {
      confirmationId,
      sessionId: securityContext.sessionId,
      action: confirmationData.action,
      method: confirmationData.method
    });
    
    return confirmationId;
  }

  async validateConfirmation(confirmationId, toolExecutionContext) {
    if (!this.isActive) {
      throw new Error('User Confirmation System not initialized');
    }

    const confirmationData = this.pendingCache.get(confirmationId);
    
    if (!confirmationData) {
      this.logger.warn('Confirmation not found', { confirmationId });
      return false;
    }
    
    // Check if confirmation has expired
    if (new Date() > new Date(confirmationData.expiresAt)) {
      this.logger.warn('Confirmation expired', { confirmationId });
      this.pendingCache.del(confirmationId);
      return false;
    }
    
    // Check if confirmation is for the correct action
    const actionMatch = this.validateActionMatch(confirmationData, toolExecutionContext);
    if (!actionMatch.valid) {
      this.logger.warn('Action mismatch in confirmation', {
        confirmationId,
        expectedAction: confirmationData.action,
        actualAction: actionMatch.actualAction
      });
      return false;
    }
    
    // Check if confirmation has been approved
    if (confirmationData.status !== 'approved') {
      this.logger.warn('Confirmation not approved', {
        confirmationId,
        status: confirmationData.status
      });
      return false;
    }
    
    // Mark confirmation as used
    confirmationData.status = 'used';
    confirmationData.usedAt = new Date().toISOString();
    confirmationData.usedFor = toolExecutionContext.toolName;
    
    // Store used confirmation
    this.confirmationCache.set(confirmationId, confirmationData, 3600); // 1 hour TTL
    
    // Remove from pending
    this.pendingCache.del(confirmationId);
    
    this.logger.info('Confirmation validated successfully', {
      confirmationId,
      toolName: toolExecutionContext.toolName
    });
    
    return true;
  }

  async approveConfirmation(confirmationId, userId, method = 'manual') {
    if (!this.isActive) {
      throw new Error('User Confirmation System not initialized');
    }

    const confirmationData = this.pendingCache.get(confirmationId);
    
    if (!confirmationData) {
      this.logger.warn('Confirmation not found for approval', { confirmationId });
      return { success: false, reason: 'Confirmation not found' };
    }
    
    // Check if confirmation has expired
    if (new Date() > new Date(confirmationData.expiresAt)) {
      this.logger.warn('Attempted to approve expired confirmation', { confirmationId });
      this.pendingCache.del(confirmationId);
      return { success: false, reason: 'Confirmation expired' };
    }
    
    // Validate user
    if (confirmationData.userId && confirmationData.userId !== userId) {
      this.logger.warn('User mismatch in confirmation approval', {
        confirmationId,
        expectedUser: confirmationData.userId,
        actualUser: userId
      });
      return { success: false, reason: 'User mismatch' };
    }
    
    // Update confirmation status
    confirmationData.status = 'approved';
    confirmationData.approvedAt = new Date().toISOString();
    confirmationData.approvedBy = userId;
    confirmationData.approvalMethod = method;
    
    // Store updated confirmation
    this.pendingCache.set(confirmationId, confirmationData);
    
    this.logger.info('Confirmation approved', {
      confirmationId,
      userId,
      method,
      action: confirmationData.action
    });
    
    return { success: true, confirmationData };
  }

  async rejectConfirmation(confirmationId, userId, reason = 'user_rejected') {
    if (!this.isActive) {
      throw new Error('User Confirmation System not initialized');
    }

    const confirmationData = this.pendingCache.get(confirmationId);
    
    if (!confirmationData) {
      return { success: false, reason: 'Confirmation not found' };
    }
    
    // Update confirmation status
    confirmationData.status = 'rejected';
    confirmationData.rejectedAt = new Date().toISOString();
    confirmationData.rejectedBy = userId;
    confirmationData.rejectionReason = reason;
    
    // Store rejected confirmation
    this.confirmationCache.set(confirmationId, confirmationData, 3600); // 1 hour TTL
    
    // Remove from pending
    this.pendingCache.del(confirmationId);
    
    this.logger.info('Confirmation rejected', {
      confirmationId,
      userId,
      reason,
      action: confirmationData.action
    });
    
    return { success: true, confirmationData };
  }

  async checkConfirmationRequired(securityContext, toolName) {
    if (!this.isActive) {
      return { required: false, reason: null };
    }

    // Check if tool requires confirmation
    if (this.isConfirmationRequiredAction(toolName)) {
      return {
        required: true,
        reason: `Tool ${toolName} requires confirmation`
      };
    }
    
    // Check for high-risk patterns in input
    const highRiskPatterns = this.detectHighRiskPatterns(securityContext.sanitizedInput);
    if (highRiskPatterns.length > 0) {
      return {
        required: true,
        reason: `High-risk patterns detected: ${highRiskPatterns.join(', ')}`
      };
    }
    
    // Check user's confirmation preferences
    const userPreferences = await this.getUserConfirmationPreferences(securityContext.userId);
    if (userPreferences.strictMode) {
      return {
        required: true,
        reason: 'User has strict confirmation mode enabled'
      };
    }
    
    return { required: false, reason: null };
  }

  determineConfirmationMethod(securityContext) {
    // Determine the best confirmation method based on context
    const userPreferences = this.getUserConfirmationPreferences(securityContext.userId);
    
    // Check if user has preferred method
    if (userPreferences.preferredMethod && 
        this.confirmationMethods.includes(userPreferences.preferredMethod)) {
      return userPreferences.preferredMethod;
    }
    
    // Default to mobile app for high-risk actions
    if (this.isHighRiskAction(securityContext.confirmationReason)) {
      return 'mobile_app';
    }
    
    // Default to voice verification for Google Home context
    if (securityContext.source === 'google_home') {
      return 'voice_verification';
    }
    
    return 'mobile_app'; // Default fallback
  }

  validateActionMatch(confirmationData, toolExecutionContext) {
    const expectedAction = confirmationData.action;
    const actualAction = toolExecutionContext.toolName;
    
    // Exact match
    if (expectedAction === actualAction) {
      return { valid: true };
    }
    
    // Check if actions are related (e.g., device_control vs light_control)
    if (this.areActionsRelated(expectedAction, actualAction)) {
      return { valid: true };
    }
    
    return {
      valid: false,
      actualAction: actualAction
    };
  }

  areActionsRelated(action1, action2) {
    // Define related action groups
    const actionGroups = {
      device_control: ['light_control', 'thermostat_control', 'smart_lock_control'],
      data_access: ['file_access', 'camera_access', 'location_access'],
      communication: ['email_send', 'sms_send', 'notification_send']
    };
    
    // Check if both actions belong to the same group
    for (const [group, actions] of Object.entries(actionGroups)) {
      if (actions.includes(action1) && actions.includes(action2)) {
        return true;
      }
    }
    
    return false;
  }

  isConfirmationRequiredAction(action) {
    return this.confirmationRequiredActions.includes(action);
  }

  isHighRiskAction(action) {
    const highRiskActions = [
      'device_control',
      'smart_lock_control',
      'payment_processing',
      'data_exfiltration'
    ];
    
    return highRiskActions.includes(action);
  }

  detectHighRiskPatterns(input) {
    const patterns = [];
    
    this.highRiskPatterns.forEach(pattern => {
      if (pattern.test(input)) {
        patterns.push(pattern.toString());
      }
    });
    
    return patterns;
  }

  async getUserConfirmationPreferences(userId) {
    // In a real implementation, this would fetch from user database
    // For now, return default preferences
    return {
      strictMode: false,
      preferredMethod: 'mobile_app',
      autoApprove: false,
      requireBiometric: false
    };
  }

  generateConfirmationId() {
    return `confirm_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  async getPendingConfirmations(userId) {
    if (!this.isActive) {
      return [];
    }

    const pendingConfirmations = [];
    const keys = this.pendingCache.keys();
    
    for (const key of keys) {
      const confirmation = this.pendingCache.get(key);
      if (confirmation && confirmation.userId === userId) {
        pendingConfirmations.push({
          id: confirmation.id,
          action: confirmation.action,
          timestamp: confirmation.timestamp,
          expiresAt: confirmation.expiresAt,
          method: confirmation.method
        });
      }
    }
    
    return pendingConfirmations;
  }

  async getConfirmationHistory(userId, limit = 50) {
    if (!this.isActive) {
      return [];
    }

    const history = [];
    const keys = this.confirmationCache.keys();
    
    for (const key of keys) {
      const confirmation = this.confirmationCache.get(key);
      if (confirmation && confirmation.userId === userId) {
        history.push({
          id: confirmation.id,
          action: confirmation.action,
          status: confirmation.status,
          timestamp: confirmation.timestamp,
          method: confirmation.method,
          approvedAt: confirmation.approvedAt,
          rejectedAt: confirmation.rejectedAt
        });
      }
    }
    
    // Sort by timestamp and limit results
    return history
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Update confirmation required actions if provided
    if (newConfig.requireConfirmationFor) {
      this.confirmationRequiredActions = [
        ...this.confirmationRequiredActions,
        ...newConfig.requireConfirmationFor
      ];
    }
  }

  getConfirmationStats() {
    return {
      active: this.isActive,
      pendingCacheSize: this.pendingCache.keys().length,
      confirmationCacheSize: this.confirmationCache.keys().length,
      confirmationRequiredActions: this.confirmationRequiredActions.length,
      highRiskPatterns: this.highRiskPatterns.length,
      confirmationMethods: this.confirmationMethods.length
    };
  }
}

module.exports = UserConfirmationSystem;
