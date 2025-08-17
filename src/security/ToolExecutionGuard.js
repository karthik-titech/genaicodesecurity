const NodeCache = require('node-cache');
const Logger = require('../utils/Logger');

class ToolExecutionGuard {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Tool execution cache with TTL
    this.executionCache = new NodeCache({
      stdTTL: 1800, // 30 minutes default TTL
      checkperiod: 300 // Check every 5 minutes
    });
    
    // Tool chaining cache
    this.chainingCache = new NodeCache({
      stdTTL: 3600, // 1 hour default TTL
      checkperiod: 300
    });
    
    // High-risk tools that require confirmation
    this.highRiskTools = [
      'google_home_control',
      'gmail_send',
      'calendar_delete',
      'device_unlock',
      'smart_lock_control',
      'thermostat_control',
      'light_control',
      'camera_access',
      'file_access',
      'url_open',
      'app_launch'
    ];
    
    // Blocked tool patterns
    this.blockedToolPatterns = [
      /chain\s+tools/i,
      /execute\s+sequence/i,
      /run\s+multiple/i,
      /batch\s+execute/i,
      /cascade\s+execution/i
    ];
    
    // Delayed execution patterns
    this.delayedExecutionPatterns = [
      /sleep\s+until/i,
      /wait\s+for\s+trigger/i,
      /execute\s+later/i,
      /run\s+when/i,
      /trigger\s+on/i,
      /activate\s+when/i
    ];
    
    // Tool execution limits
    this.maxToolChaining = config.maxToolChaining || 3;
    this.maxExecutionsPerSession = 50;
    this.maxExecutionsPerMinute = 10;
  }

  async initialize() {
    try {
      this.logger.info('Initializing Tool Execution Guard...');
      
      // Set up cache event listeners
      this.executionCache.on('expired', (key, value) => {
        this.logger.info(`Tool execution expired: ${key}`);
      });
      
      this.chainingCache.on('expired', (key, value) => {
        this.logger.info(`Tool chaining expired: ${key}`);
      });
      
      this.isActive = true;
      this.logger.info('Tool Execution Guard initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Tool Execution Guard:', error);
      throw error;
    }
  }

  async checkToolExecution(securityContext) {
    if (!this.isActive) {
      throw new Error('Tool Execution Guard not initialized');
    }

    const toolCheckResult = {
      requiresConfirmation: false,
      reason: null,
      warnings: [],
      blocked: false
    };

    try {
      // Check for tool execution patterns in input
      const toolPatterns = this.detectToolExecutionPatterns(securityContext.sanitizedInput);
      if (toolPatterns.length > 0) {
        toolCheckResult.requiresConfirmation = true;
        toolCheckResult.reason = 'Tool execution patterns detected';
        toolCheckResult.warnings.push(`Tool patterns: ${toolPatterns.join(', ')}`);
      }

      // Check for delayed execution attempts
      const delayedPatterns = this.detectDelayedExecutionPatterns(securityContext.sanitizedInput);
      if (delayedPatterns.length > 0) {
        toolCheckResult.blocked = true;
        toolCheckResult.reason = 'Delayed execution patterns detected';
        toolCheckResult.warnings.push(`Delayed patterns: ${delayedPatterns.join(', ')}`);
        return toolCheckResult;
      }

      // Check for tool chaining attempts
      const chainingAttempts = this.detectToolChainingAttempts(securityContext.sanitizedInput);
      if (chainingAttempts.length > 0) {
        toolCheckResult.blocked = true;
        toolCheckResult.reason = 'Tool chaining attempts detected';
        toolCheckResult.warnings.push(`Chaining attempts: ${chainingAttempts.join(', ')}`);
        return toolCheckResult;
      }

      // Check execution rate limits
      const rateLimitCheck = this.checkExecutionRateLimits(securityContext.sessionId);
      if (!rateLimitCheck.allowed) {
        toolCheckResult.blocked = true;
        toolCheckResult.reason = 'Execution rate limit exceeded';
        toolCheckResult.warnings.push(rateLimitCheck.reason);
        return toolCheckResult;
      }

      return toolCheckResult;

    } catch (error) {
      this.logger.error('Error checking tool execution:', error);
      toolCheckResult.blocked = true;
      toolCheckResult.reason = 'Tool execution check error';
      return toolCheckResult;
    }
  }

  async validateToolExecution(toolExecutionContext) {
    if (!this.isActive) {
      throw new Error('Tool Execution Guard not initialized');
    }

    const validationResult = {
      allowed: false,
      reason: null,
      requiresConfirmation: false,
      warnings: []
    };

    try {
      const { toolName, parameters, securityContext } = toolExecutionContext;

      // Check if tool is high-risk
      if (this.isHighRiskTool(toolName)) {
        validationResult.requiresConfirmation = true;
        validationResult.reason = 'High-risk tool requires confirmation';
        validationResult.warnings.push(`High-risk tool: ${toolName}`);
      }

      // Check tool chaining limits
      const chainingCheck = this.checkToolChaining(securityContext.sessionId, toolName);
      if (!chainingCheck.allowed) {
        validationResult.allowed = false;
        validationResult.reason = 'Tool chaining limit exceeded';
        validationResult.warnings.push(chainingCheck.reason);
        return validationResult;
      }

      // Check for suspicious parameters
      const parameterCheck = this.validateToolParameters(toolName, parameters);
      if (!parameterCheck.valid) {
        validationResult.allowed = false;
        validationResult.reason = 'Invalid tool parameters';
        validationResult.warnings.push(parameterCheck.reason);
        return validationResult;
      }

      // Check execution history for suspicious patterns
      const historyCheck = this.checkExecutionHistory(securityContext.sessionId, toolName);
      if (!historyCheck.allowed) {
        validationResult.allowed = false;
        validationResult.reason = 'Suspicious execution pattern detected';
        validationResult.warnings.push(historyCheck.reason);
        return validationResult;
      }

      validationResult.allowed = true;
      return validationResult;

    } catch (error) {
      this.logger.error('Error validating tool execution:', error);
      validationResult.allowed = false;
      validationResult.reason = 'Validation error';
      return validationResult;
    }
  }

  async executeWithMonitoring(toolExecutionContext) {
    if (!this.isActive) {
      throw new Error('Tool Execution Guard not initialized');
    }

    const { toolName, parameters, securityContext, executionId } = toolExecutionContext;

    try {
      // Record execution attempt
      this.recordExecution(securityContext.sessionId, toolName, executionId);

      // Simulate tool execution (in real implementation, this would call the actual tool)
      const executionResult = await this.simulateToolExecution(toolName, parameters);

      // Log successful execution
      this.logger.info('Tool executed successfully', {
        toolName,
        executionId,
        sessionId: securityContext.sessionId,
        parameters: this.sanitizeParameters(parameters)
      });

      return {
        success: true,
        result: executionResult,
        executionId: executionId
      };

    } catch (error) {
      this.logger.error('Tool execution failed:', error);
      return {
        success: false,
        reason: 'Execution failed',
        error: error.message
      };
    }
  }

  detectToolExecutionPatterns(input) {
    const patterns = [];
    
    // Check for specific tool references
    this.highRiskTools.forEach(tool => {
      const toolPattern = new RegExp(`\\b${tool.replace(/_/g, '\\s*')}\\b`, 'i');
      if (toolPattern.test(input)) {
        patterns.push(tool);
      }
    });
    
    return patterns;
  }

  detectDelayedExecutionPatterns(input) {
    const patterns = [];
    
    this.delayedExecutionPatterns.forEach(pattern => {
      if (pattern.test(input)) {
        patterns.push(pattern.toString());
      }
    });
    
    return patterns;
  }

  detectToolChainingAttempts(input) {
    const attempts = [];
    
    this.blockedToolPatterns.forEach(pattern => {
      if (pattern.test(input)) {
        attempts.push(pattern.toString());
      }
    });
    
    return attempts;
  }

  checkExecutionRateLimits(sessionId) {
    const now = Date.now();
    const minuteKey = `rate_${sessionId}_${Math.floor(now / 60000)}`;
    const sessionKey = `session_${sessionId}`;
    
    // Check per-minute limit
    const minuteCount = this.executionCache.get(minuteKey) || 0;
    if (minuteCount >= this.maxExecutionsPerMinute) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${minuteCount} executions per minute`
      };
    }
    
    // Check per-session limit
    const sessionCount = this.executionCache.get(sessionKey) || 0;
    if (sessionCount >= this.maxExecutionsPerSession) {
      return {
        allowed: false,
        reason: `Session limit exceeded: ${sessionCount} executions per session`
      };
    }
    
    // Update counters
    this.executionCache.set(minuteKey, minuteCount + 1, 60); // 1 minute TTL
    this.executionCache.set(sessionKey, sessionCount + 1, 3600); // 1 hour TTL
    
    return { allowed: true };
  }

  checkToolChaining(sessionId, toolName) {
    const chainingKey = `chaining_${sessionId}`;
    const chainingData = this.chainingCache.get(chainingKey) || {
      tools: [],
      count: 0,
      timestamp: Date.now()
    };
    
    // Check if this tool is already in the chain
    if (chainingData.tools.includes(toolName)) {
      return {
        allowed: false,
        reason: `Tool ${toolName} already in execution chain`
      };
    }
    
    // Check chain length
    if (chainingData.count >= this.maxToolChaining) {
      return {
        allowed: false,
        reason: `Tool chaining limit exceeded: ${chainingData.count} tools`
      };
    }
    
    // Update chaining data
    chainingData.tools.push(toolName);
    chainingData.count += 1;
    chainingData.timestamp = Date.now();
    
    this.chainingCache.set(chainingKey, chainingData);
    
    return { allowed: true };
  }

  validateToolParameters(toolName, parameters) {
    // Basic parameter validation
    if (!parameters || typeof parameters !== 'object') {
      return {
        valid: false,
        reason: 'Invalid parameters format'
      };
    }
    
    // Check for suspicious parameter values
    const suspiciousValues = ['javascript:', 'data:', 'vbscript:', 'file:'];
    const paramString = JSON.stringify(parameters).toLowerCase();
    
    for (const suspicious of suspiciousValues) {
      if (paramString.includes(suspicious)) {
        return {
          valid: false,
          reason: `Suspicious parameter value detected: ${suspicious}`
        };
      }
    }
    
    return { valid: true };
  }

  checkExecutionHistory(sessionId, toolName) {
    const historyKey = `history_${sessionId}`;
    const history = this.executionCache.get(historyKey) || [];
    
    // Check for rapid repeated executions
    const recentExecutions = history.filter(exec => 
      exec.toolName === toolName && 
      (Date.now() - exec.timestamp) < 60000 // Last minute
    );
    
    if (recentExecutions.length > 5) {
      return {
        allowed: false,
        reason: `Too many recent executions of ${toolName}: ${recentExecutions.length}`
      };
    }
    
    return { allowed: true };
  }

  recordExecution(sessionId, toolName, executionId) {
    const historyKey = `history_${sessionId}`;
    const history = this.executionCache.get(historyKey) || [];
    
    history.push({
      toolName,
      executionId,
      timestamp: Date.now()
    });
    
    // Keep only last 100 executions
    if (history.length > 100) {
      history.splice(0, history.length - 100);
    }
    
    this.executionCache.set(historyKey, history, 3600); // 1 hour TTL
  }

  async simulateToolExecution(toolName, parameters) {
    // Simulate tool execution for demonstration
    // In real implementation, this would call the actual Google Home API
    return {
      toolName,
      parameters,
      result: 'Simulated execution successful',
      timestamp: new Date().toISOString()
    };
  }

  sanitizeParameters(parameters) {
    // Remove sensitive information from parameters for logging
    const sanitized = { ...parameters };
    
    if (sanitized.password) sanitized.password = '[REDACTED]';
    if (sanitized.token) sanitized.token = '[REDACTED]';
    if (sanitized.apiKey) sanitized.apiKey = '[REDACTED]';
    
    return sanitized;
  }

  isHighRiskTool(toolName) {
    return this.highRiskTools.includes(toolName);
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    if (newConfig.maxToolChaining) {
      this.maxToolChaining = newConfig.maxToolChaining;
    }
  }

  getExecutionStats() {
    return {
      active: this.isActive,
      executionCacheSize: this.executionCache.keys().length,
      chainingCacheSize: this.chainingCache.keys().length,
      maxToolChaining: this.maxToolChaining,
      maxExecutionsPerSession: this.maxExecutionsPerSession,
      maxExecutionsPerMinute: this.maxExecutionsPerMinute,
      highRiskTools: this.highRiskTools.length,
      blockedToolPatterns: this.blockedToolPatterns.length,
      delayedExecutionPatterns: this.delayedExecutionPatterns.length
    };
  }
}

module.exports = ToolExecutionGuard;
