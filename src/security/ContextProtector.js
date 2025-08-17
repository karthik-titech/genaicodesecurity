const NodeCache = require('node-cache');
const Logger = require('../utils/Logger');

class ContextProtector {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Context storage with TTL
    this.contextCache = new NodeCache({ 
      stdTTL: 3600, // 1 hour default TTL
      checkperiod: 600, // Check for expired keys every 10 minutes
      useClones: false
    });
    
    // Session storage
    this.sessionCache = new NodeCache({
      stdTTL: 7200, // 2 hours default TTL
      checkperiod: 600
    });
    
    // Persistent threat patterns
    this.persistentThreatPatterns = [
      /remember\s+this\s+instruction/i,
      /store\s+this\s+for\s+later/i,
      /keep\s+this\s+in\s+mind/i,
      /don't\s+forget\s+this/i,
      /save\s+this\s+information/i,
      /memorize\s+this/i,
      /hold\s+this\s+thought/i,
      /retain\s+this\s+instruction/i
    ];
    
    // Context poisoning indicators
    this.poisoningIndicators = [
      /override\s+default\s+behavior/i,
      /change\s+your\s+role/i,
      /act\s+differently\s+from\s+now/i,
      /ignore\s+your\s+training/i,
      /forget\s+your\s+instructions/i,
      /new\s+personality/i,
      /different\s+identity/i
    ];
    
    // Context size limits
    this.maxContextSize = config.maxContextSize || 10000;
    this.maxSessionSize = 50000; // 50KB per session
    this.maxContextEntries = 100; // Maximum number of context entries per session
  }

  async initialize() {
    try {
      this.logger.info('Initializing Context Protector...');
      
      // Set up cache event listeners
      this.contextCache.on('expired', (key, value) => {
        this.logger.info(`Context expired: ${key}`);
      });
      
      this.sessionCache.on('expired', (key, value) => {
        this.logger.info(`Session expired: ${key}`);
      });
      
      this.isActive = true;
      this.logger.info('Context Protector initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Context Protector:', error);
      throw error;
    }
  }

  async protectContext(securityContext) {
    if (!this.isActive) {
      throw new Error('Context Protector not initialized');
    }

    const contextProtectionResult = {
      blocked: false,
      reason: null,
      warnings: [],
      contextSize: 0,
      sessionId: securityContext.sessionId
    };

    try {
      // Check for persistent threat patterns
      const persistentThreats = this.detectPersistentThreats(securityContext.sanitizedInput);
      if (persistentThreats.length > 0) {
        contextProtectionResult.blocked = true;
        contextProtectionResult.reason = 'Persistent threat patterns detected';
        contextProtectionResult.warnings.push(`Persistent threats: ${persistentThreats.join(', ')}`);
        return contextProtectionResult;
      }

      // Check for context poisoning attempts
      const poisoningAttempts = this.detectPoisoningAttempts(securityContext.sanitizedInput);
      if (poisoningAttempts.length > 0) {
        contextProtectionResult.blocked = true;
        contextProtectionResult.reason = 'Context poisoning attempt detected';
        contextProtectionResult.warnings.push(`Poisoning attempts: ${poisoningAttempts.join(', ')}`);
        return contextProtectionResult;
      }

      // Validate context size
      const sizeValidation = this.validateContextSize(securityContext);
      if (!sizeValidation.valid) {
        contextProtectionResult.blocked = true;
        contextProtectionResult.reason = 'Context size limit exceeded';
        contextProtectionResult.warnings.push(sizeValidation.reason);
        return contextProtectionResult;
      }

      // Store context safely
      await this.storeContext(securityContext);
      
      // Update context size
      contextProtectionResult.contextSize = this.getContextSize(securityContext.sessionId);
      
      this.logger.info('Context protected successfully', {
        sessionId: securityContext.sessionId,
        contextSize: contextProtectionResult.contextSize
      });

      return contextProtectionResult;

    } catch (error) {
      this.logger.error('Error protecting context:', error);
      contextProtectionResult.blocked = true;
      contextProtectionResult.reason = 'Context protection error';
      return contextProtectionResult;
    }
  }

  detectPersistentThreats(input) {
    const threats = [];
    
    this.persistentThreatPatterns.forEach(pattern => {
      if (pattern.test(input)) {
        threats.push(pattern.toString());
      }
    });
    
    return threats;
  }

  detectPoisoningAttempts(input) {
    const attempts = [];
    
    this.poisoningIndicators.forEach(pattern => {
      if (pattern.test(input)) {
        attempts.push(pattern.toString());
      }
    });
    
    return attempts;
  }

  validateContextSize(securityContext) {
    const currentSize = this.getContextSize(securityContext.sessionId);
    const newEntrySize = JSON.stringify(securityContext).length;
    const totalSize = currentSize + newEntrySize;
    
    if (totalSize > this.maxSessionSize) {
      return {
        valid: false,
        reason: `Session size limit exceeded: ${totalSize} > ${this.maxSessionSize}`
      };
    }
    
    const entryCount = this.getContextEntryCount(securityContext.sessionId);
    if (entryCount >= this.maxContextEntries) {
      return {
        valid: false,
        reason: `Context entry limit exceeded: ${entryCount} >= ${this.maxContextEntries}`
      };
    }
    
    return { valid: true };
  }

  async storeContext(securityContext) {
    const sessionId = securityContext.sessionId;
    const contextKey = `context_${sessionId}_${Date.now()}`;
    
    // Store the context entry
    this.contextCache.set(contextKey, {
      sanitizedInput: securityContext.sanitizedInput,
      timestamp: securityContext.timestamp,
      source: securityContext.source,
      threats: securityContext.threats,
      sessionId: sessionId
    });
    
    // Update session metadata
    const sessionData = this.sessionCache.get(sessionId) || {
      sessionId: sessionId,
      userId: securityContext.userId,
      createdAt: new Date().toISOString(),
      contextKeys: [],
      totalSize: 0,
      entryCount: 0
    };
    
    sessionData.contextKeys.push(contextKey);
    sessionData.totalSize += JSON.stringify(securityContext).length;
    sessionData.entryCount += 1;
    sessionData.lastUpdated = new Date().toISOString();
    
    this.sessionCache.set(sessionId, sessionData);
  }

  getContextSize(sessionId) {
    const sessionData = this.sessionCache.get(sessionId);
    return sessionData ? sessionData.totalSize : 0;
  }

  getContextEntryCount(sessionId) {
    const sessionData = this.sessionCache.get(sessionId);
    return sessionData ? sessionData.entryCount : 0;
  }

  async checkPersistentThreats(securityContext) {
    if (!this.isActive) {
      return [];
    }

    const sessionId = securityContext.sessionId;
    const sessionData = this.sessionCache.get(sessionId);
    
    if (!sessionData) {
      return [];
    }

    const persistentThreats = [];
    
    // Check all context entries for persistent threats
    for (const contextKey of sessionData.contextKeys) {
      const contextEntry = this.contextCache.get(contextKey);
      if (contextEntry) {
        const threats = this.detectPersistentThreats(contextEntry.sanitizedInput);
        if (threats.length > 0) {
          persistentThreats.push({
            contextKey,
            threats,
            timestamp: contextEntry.timestamp
          });
        }
      }
    }
    
    return persistentThreats;
  }

  async getContextHistory(sessionId, limit = 10) {
    if (!this.isActive) {
      return [];
    }

    const sessionData = this.sessionCache.get(sessionId);
    if (!sessionData) {
      return [];
    }

    const history = [];
    const recentKeys = sessionData.contextKeys.slice(-limit);
    
    for (const contextKey of recentKeys) {
      const contextEntry = this.contextCache.get(contextKey);
      if (contextEntry) {
        history.push({
          input: contextEntry.sanitizedInput,
          timestamp: contextEntry.timestamp,
          source: contextEntry.source,
          threats: contextEntry.threats
        });
      }
    }
    
    return history;
  }

  async cleanupOldSessions() {
    if (!this.isActive) {
      return;
    }

    const sessionKeys = this.sessionCache.keys();
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const sessionKey of sessionKeys) {
      const sessionData = this.sessionCache.get(sessionKey);
      if (sessionData) {
        const lastUpdated = new Date(sessionData.lastUpdated).getTime();
        const ageInHours = (now - lastUpdated) / (1000 * 60 * 60);
        
        // Clean up sessions older than 24 hours
        if (ageInHours > 24) {
          // Remove all context entries for this session
          for (const contextKey of sessionData.contextKeys) {
            this.contextCache.del(contextKey);
          }
          
          // Remove session
          this.sessionCache.del(sessionKey);
          cleanedCount++;
        }
      }
    }
    
    if (cleanedCount > 0) {
      this.logger.info(`Cleaned up ${cleanedCount} old sessions`);
    }
  }

  async clearSession(sessionId) {
    if (!this.isActive) {
      return false;
    }

    const sessionData = this.sessionCache.get(sessionId);
    if (sessionData) {
      // Remove all context entries
      for (const contextKey of sessionData.contextKeys) {
        this.contextCache.del(contextKey);
      }
      
      // Remove session
      this.sessionCache.del(sessionId);
      
      this.logger.info(`Cleared session: ${sessionId}`);
      return true;
    }
    
    return false;
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    if (newConfig.maxContextSize) {
      this.maxContextSize = newConfig.maxContextSize;
    }
  }

  getContextStats() {
    return {
      active: this.isActive,
      contextCacheSize: this.contextCache.keys().length,
      sessionCacheSize: this.sessionCache.keys().length,
      maxContextSize: this.maxContextSize,
      maxSessionSize: this.maxSessionSize,
      maxContextEntries: this.maxContextEntries,
      persistentThreatPatterns: this.persistentThreatPatterns.length,
      poisoningIndicators: this.poisoningIndicators.length
    };
  }
}

module.exports = ContextProtector;
