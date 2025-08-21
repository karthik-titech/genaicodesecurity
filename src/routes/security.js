const express = require('express');
const router = express.Router();
const { body, validationResult, param, query } = require('express-validator');
const Logger = require('../utils/Logger');

class SecurityRoutes {
  constructor() {
    this.logger = new Logger();
    this.setupRoutes();
  }

  setupRoutes() {
    // Get security status
    router.get('/status', this.getSecurityStatus.bind(this));
    
    // Get security statistics
    router.get('/stats', this.getSecurityStats.bind(this));
    
    // Update security configuration with enhanced validation
    router.post('/config', [
      body('strictMode').optional().isBoolean(),
      body('maxContextSize').optional().isInt({ min: 1000, max: 100000 }),
      body('maxToolChaining').optional().isInt({ min: 1, max: 10 }),
      body('requireConfirmationFor').optional().isArray(),
      body('requireConfirmationFor.*').optional().isString().isLength({ min: 1, max: 50 }),
      body('blockedPatterns').optional().isArray(),
      body('blockedPatterns.*').optional().isString().isLength({ min: 1, max: 200 }),
      body('threatThresholds.low').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.medium').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.high').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.critical').optional().isFloat({ min: 0, max: 1 })
    ], this.updateSecurityConfig.bind(this));
    
    // Get configuration
    router.get('/config', this.getConfiguration.bind(this));
    
    // Update secrets with enhanced validation
    router.post('/secrets', [
      body('key').isString().isLength({ min: 1, max: 100 }),
      body('value').isString().isLength({ min: 1, max: 1000 })
    ], this.updateSecret.bind(this));
    
    // Get secrets summary
    router.get('/secrets', this.getSecretsSummary.bind(this));
    
    // Get threat statistics with validation
    router.get('/threats', [
      query('timeRange').optional().isIn(['1h', '24h', '7d', '30d']),
      query('type').optional().isIn(['all', 'prompt-injection', 'data-exfiltration', 'device-control', 'social-engineering']),
      query('limit').optional().isInt({ min: 1, max: 1000 }),
      query('offset').optional().isInt({ min: 0 })
    ], this.getThreatStats.bind(this));
    
    // Get access control statistics with validation
    router.get('/access', [
      query('timeRange').optional().isIn(['1h', '24h', '7d', '30d']),
      query('userId').optional().isString().isLength({ min: 1, max: 100 })
    ], this.getAccessStats.bind(this));
    
    // Get confirmation statistics with validation
    router.get('/confirmations', [
      query('timeRange').optional().isIn(['1h', '24h', '7d', '30d']),
      query('status').optional().isIn(['pending', 'approved', 'denied', 'expired'])
    ], this.getConfirmationStats.bind(this));
    
    // Test security patch with enhanced validation
    router.post('/test', [
      body('input').isString().isLength({ min: 1, max: 5000 }).escape(),
      body('source').optional().isString().isLength({ min: 1, max: 50 }),
      body('userId').optional().isString().isLength({ min: 1, max: 100 }),
      body('context').optional().isObject(),
      body('expectedResult').optional().isObject()
    ], this.testSecurityPatch.bind(this));
    
    // Get security logs with validation
    router.get('/logs', [
      query('lines').optional().isInt({ min: 1, max: 1000 }),
      query('type').optional().isIn(['all', 'security', 'access', 'error', 'threat', 'audit']),
      query('level').optional().isIn(['info', 'warn', 'error', 'security', 'threat']),
      query('startDate').optional().isISO8601(),
      query('endDate').optional().isISO8601()
    ], this.getSecurityLogs.bind(this));
    
    // Clear security cache
    router.post('/clear-cache', this.clearSecurityCache.bind(this));

    // Add validation error handler
    router.use(this.handleValidationErrors.bind(this));
  }

  // Handle validation errors
  handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Input validation failed',
          details: errors.array().map(err => ({
            field: err.path,
            message: err.msg,
            value: err.value
          })),
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
    next();
  }

  // Sanitize input data
  sanitizeInput(data) {
    if (typeof data === 'string') {
      return data
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/data:text\/html/gi, '')
        .trim();
    } else if (typeof data === 'object' && data !== null) {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeInput(value);
      }
      return sanitized;
    }
    return data;
  }

  async getSecurityStatus(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Security patch not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const status = securityPatch.getSecurityStatus();
      
      this.logger.access('Security status requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        ...status,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting security status:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(500).json({ 
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async getSecurityStats(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Security patch not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const stats = {
        inputSanitizer: securityPatch.securityLayers.inputSanitizer.getSanitizationStats(),
        contextProtector: securityPatch.securityLayers.contextProtector.getContextStats(),
        toolExecutionGuard: securityPatch.securityLayers.toolExecutionGuard.getExecutionStats(),
        userConfirmationSystem: securityPatch.securityLayers.userConfirmationSystem.getConfirmationStats(),
        accessControlManager: securityPatch.securityLayers.accessControlManager.getAccessControlStats(),
        threatDetector: securityPatch.securityLayers.threatDetector.getThreatDetectionStats()
      };

      this.logger.access('Security stats requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        ...stats,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting security stats:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(500).json({ 
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async updateSecurityConfig(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      const configManager = req.app.locals.configManager;
      
      if (!securityPatch || !configManager) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Security patch not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      // Sanitize input
      const sanitizedBody = this.sanitizeInput(req.body);
      const newConfig = sanitizedBody;
      
      // Update configuration in config manager
      for (const [key, value] of Object.entries(newConfig)) {
        await configManager.updateConfig(key, value);
      }
      
      // Update security patch configuration
      await securityPatch.updateSecurityConfig(newConfig);

      this.logger.audit('Security configuration updated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        config: newConfig,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({ 
        success: true, 
        message: 'Security configuration updated successfully',
        config: securityPatch.securityConfig,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error updating security config:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(500).json({ 
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async getConfiguration(req, res) {
    try {
      const configManager = req.app.locals.configManager;
      if (!configManager) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Configuration manager not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const config = configManager.getFullConfig();
      
      this.logger.access('Configuration requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        ...config,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting configuration:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(500).json({ 
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async updateSecret(req, res) {
    try {
      const configManager = req.app.locals.configManager;
      if (!configManager) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Configuration manager not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      // Sanitize input
      const sanitizedBody = this.sanitizeInput(req.body);
      const { key, value } = sanitizedBody;
      await configManager.updateSecret(key, value);

      this.logger.audit('Secret updated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        key: key,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({ 
        success: true, 
        message: 'Secret updated successfully',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error updating secret:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(500).json({ 
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async getSecretsSummary(req, res) {
    try {
      const configManager = req.app.locals.configManager;
      if (!configManager) {
        return res.status(503).json({ error: 'Configuration manager not available' });
      }

      const secrets = configManager.getSecretsSummary();
      
      this.logger.access('Secrets summary requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json(secrets);
    } catch (error) {
      this.logger.error('Error getting secrets summary:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getThreatStats(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ error: 'Security patch not available' });
      }

      const timeRange = req.query.timeRange || '24h';
      const stats = await securityPatch.securityLayers.threatDetector.getThreatStatistics(timeRange);

      this.logger.access('Threat stats requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timeRange
      });

      res.json(stats);
    } catch (error) {
      this.logger.error('Error getting threat stats:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getAccessStats(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ error: 'Security patch not available' });
      }

      const stats = securityPatch.securityLayers.accessControlManager.getAccessControlStats();

      this.logger.access('Access stats requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json(stats);
    } catch (error) {
      this.logger.error('Error getting access stats:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getConfirmationStats(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ error: 'Security patch not available' });
      }

      const stats = securityPatch.securityLayers.userConfirmationSystem.getConfirmationStats();

      this.logger.access('Confirmation stats requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json(stats);
    } catch (error) {
      this.logger.error('Error getting confirmation stats:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async testSecurityPatch(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ 
          error: 'Validation failed', 
          details: errors.array() 
        });
      }

      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ error: 'Security patch not available' });
      }

      const { input, source = 'test', userId = 'test-user' } = req.body;
      
      // Create a test session
      const sessionId = `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      // Process input through security patch
      const result = await securityPatch.processInput(input, {
        sessionId,
        userId,
        source
      });

      this.logger.audit('Security patch test performed', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        input: input.substring(0, 100), // Truncate for logging
        source,
        userId,
        result: {
          blocked: result.blocked,
          threats: result.threats.length,
          requiresConfirmation: result.requiresConfirmation
        }
      });

      res.json({
        success: true,
        result,
        testInfo: {
          input: input.substring(0, 100),
          source,
          userId,
          sessionId
        }
      });
    } catch (error) {
      this.logger.error('Error testing security patch:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getSecurityLogs(req, res) {
    try {
      const fs = require('fs');
      const path = require('path');
      
      const logType = req.query.type || 'security-patch';
      const lines = parseInt(req.query.lines) || 100;
      
      const logFiles = {
        'security-patch': 'logs/security-patch.log',
        'security-events': 'logs/security-events.log',
        'security-patch-error': 'logs/security-patch-error.log'
      };
      
      const logFile = logFiles[logType];
      if (!logFile) {
        return res.status(400).json({ error: 'Invalid log type' });
      }
      
      const logPath = path.join(__dirname, '../../', logFile);
      
      if (!fs.existsSync(logPath)) {
        return res.json({ logs: [], message: 'Log file not found' });
      }
      
      // Read last N lines from log file
      const content = fs.readFileSync(logPath, 'utf8');
      const logLines = content.split('\n').filter(line => line.trim()).slice(-lines);
      
      this.logger.access('Security logs requested', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        logType,
        lines
      });

      res.json({
        logs: logLines,
        logType,
        totalLines: logLines.length
      });
    } catch (error) {
      this.logger.error('Error getting security logs:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async clearSecurityCache(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      if (!securityPatch) {
        return res.status(503).json({ error: 'Security patch not available' });
      }

      // Clear all caches
      Object.values(securityPatch.securityLayers).forEach(layer => {
        if (layer.contextCache) layer.contextCache.flushAll();
        if (layer.sessionCache) layer.sessionCache.flushAll();
        if (layer.executionCache) layer.executionCache.flushAll();
        if (layer.chainingCache) layer.chainingCache.flushAll();
        if (layer.confirmationCache) layer.confirmationCache.flushAll();
        if (layer.pendingCache) layer.pendingCache.flushAll();
        if (layer.accessCache) layer.accessCache.flushAll();
        if (layer.permissionsCache) layer.permissionsCache.flushAll();
        if (layer.deviceCache) layer.deviceCache.flushAll();
        if (layer.threatCache) layer.threatCache.flushAll();
        if (layer.globalThreatCache) layer.globalThreatCache.flushAll();
      });

      this.logger.audit('Security cache cleared', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({ 
        success: true, 
        message: 'Security cache cleared successfully' 
      });
    } catch (error) {
      this.logger.error('Error clearing security cache:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

// Initialize routes
const securityRoutes = new SecurityRoutes();

module.exports = router;
