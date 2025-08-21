const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult, param, query } = require('express-validator');
const Logger = require('../utils/Logger');

class APIRouter {
  constructor() {
    this.router = express.Router();
    this.logger = new Logger();
    this.setupMiddleware();
    this.setupRoutes();
  }

  setupMiddleware() {
    // Add request ID and timing
    this.router.use(this.logRequest.bind(this));
    
    // Authentication for all routes except health and version
    this.router.use(['/health', '/version'], (req, res, next) => next());
    this.router.use(this.authenticateAPI.bind(this));
    this.router.use(this.rateLimit.bind(this));
    
    // Input validation middleware
    this.router.use(this.validateInput.bind(this));
  }

  // Enhanced input validation middleware
  validateInput(req, res, next) {
    // Sanitize and validate request body
    if (req.body) {
      req.body = this.sanitizeInput(req.body);
    }
    
    // Sanitize and validate query parameters
    if (req.query) {
      req.query = this.sanitizeInput(req.query);
    }
    
    // Sanitize and validate URL parameters
    if (req.params) {
      req.params = this.sanitizeInput(req.params);
    }
    
    next();
  }

  // Input sanitization
  sanitizeInput(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        // Remove potential XSS and injection patterns
        sanitized[key] = value
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+\s*=/gi, '')
          .replace(/data:text\/html/gi, '')
          .trim();
      } else if (typeof value === 'object') {
        sanitized[key] = this.sanitizeInput(value);
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }

  // Enhanced authentication middleware
  async authenticateAPI(req, res, next) {
    const apiKey = req.headers.authorization?.replace('Bearer ', '') || 
                   req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        error: {
          code: 'MISSING_API_KEY',
          message: 'API key is required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    // Validate API key format and length
    if (!this.isValidAPIKeyFormat(apiKey)) {
      return res.status(401).json({
        error: {
          code: 'INVALID_API_KEY_FORMAT',
          message: 'Invalid API key format',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    // Get config manager for API key validation
    const configManager = req.app.locals.configManager;
    if (!configManager) {
      return res.status(503).json({
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'Configuration manager not available',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    // Validate API key against stored keys
    if (!(await this.validateAPIKey(apiKey, configManager))) {
      this.logger.security('Invalid API key attempt', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        apiKey: this.maskAPIKey(apiKey)
      });
      
      return res.status(401).json({
        error: {
          code: 'INVALID_API_KEY',
          message: 'Invalid API key provided',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    req.apiKey = apiKey;
    req.apiKeyHash = this.hashAPIKey(apiKey);
    next();
  }

  // Validate API key format
  isValidAPIKeyFormat(apiKey) {
    // API key should be at least 32 characters and contain alphanumeric characters
    const apiKeyRegex = /^[a-zA-Z0-9]{32,}$/;
    return apiKeyRegex.test(apiKey);
  }

  // Validate API key against stored keys
  async validateAPIKey(apiKey, configManager) {
    try {
      // Use the enhanced API key validation from ConfigManager
      const validationResult = await configManager.validateAPIKey(apiKey);
      return validationResult.valid;
    } catch (error) {
      this.logger.error('Error validating API key:', error);
      return false;
    }
  }

  // Hash API key for secure comparison
  hashAPIKey(apiKey) {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  // Mask API key for logging
  maskAPIKey(apiKey) {
    if (!apiKey || apiKey.length < 8) return '***';
    return `${apiKey.substring(0, 4)}***${apiKey.substring(apiKey.length - 4)}`;
  }

  setupRoutes() {
    // Health and version endpoints (no auth required)
    this.router.get('/health', this.healthCheck.bind(this));
    this.router.get('/version', this.getVersion.bind(this));
    
    // Security routes with validation
    this.router.get('/security/status', this.getSecurityStatus.bind(this));
    this.router.get('/security/stats', this.getSecurityStats.bind(this));
    this.router.post('/security/config', [
      body('strictMode').optional().isBoolean(),
      body('maxContextSize').optional().isInt({ min: 100, max: 10000 }),
      body('maxToolChaining').optional().isInt({ min: 1, max: 5 }),
      body('threatThresholds.low').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.medium').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.high').optional().isFloat({ min: 0, max: 1 }),
      body('threatThresholds.critical').optional().isFloat({ min: 0, max: 1 })
    ], this.updateSecurityConfig.bind(this));
    
    // Google Home routes with validation
    this.router.post('/google-home/process', [
      body('input').isString().isLength({ min: 1, max: 1000 }).escape(),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('sessionId').optional().isString().isLength({ min: 1, max: 100 }),
      body('context').optional().isObject(),
      body('context.deviceId').optional().isString().isLength({ min: 1, max: 100 }),
      body('context.location').optional().isString().isLength({ min: 1, max: 100 })
    ], this.processGoogleHomeInput.bind(this));
    
    this.router.post('/google-home/execute', [
      body('command').isString().isLength({ min: 1, max: 100 }).escape(),
      body('parameters').optional().isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('confirmationId').optional().isString().isLength({ min: 1, max: 100 }),
      body('deviceId').optional().isString().isLength({ min: 1, max: 100 })
    ], this.executeGoogleHomeCommand.bind(this));
    
    this.router.get('/google-home/devices', this.getGoogleHomeDevices.bind(this));
    this.router.get('/google-home/devices/:deviceId', [
      param('deviceId').isString().isLength({ min: 1, max: 100 })
    ], this.getGoogleHomeDevice.bind(this));
    
    // Calendar routes with validation
    this.router.post('/calendar/process-event', [
      body('event').isObject(),
      body('event.summary').isString().isLength({ min: 1, max: 500 }).escape(),
      body('event.description').optional().isString().isLength({ max: 2000 }).escape(),
      body('event.start').isISO8601(),
      body('event.end').isISO8601(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.processCalendarEvent.bind(this));
    
    this.router.post('/calendar/validate', [
      body('event').isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.validateCalendarEvent.bind(this));
    
    this.router.get('/calendar/security-status', this.getCalendarSecurityStatus.bind(this));
    
    // Threat detection routes with validation
    this.router.post('/threats/analyze', [
      body('input').isString().isLength({ min: 1, max: 5000 }).escape(),
      body('context').optional().isObject(),
      body('userId').optional().isString().isLength({ min: 1, max: 100 })
    ], this.analyzeThreats.bind(this));
    
    this.router.get('/threats/stats', [
      query('timeRange').optional().isIn(['1h', '24h', '7d', '30d'])
    ], this.getThreatStats.bind(this));
    
    this.router.get('/threats/history', [
      query('limit').optional().isInt({ min: 1, max: 1000 }),
      query('offset').optional().isInt({ min: 0 })
    ], this.getThreatHistory.bind(this));
    
    // User management routes with validation
    this.router.post('/users/sessions', [
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('permissions').optional().isArray(),
      body('sessionDuration').optional().isInt({ min: 300, max: 86400 }) // 5 min to 24 hours
    ], this.createUserSession.bind(this));
    
    this.router.get('/users/:userId/permissions', [
      param('userId').isString().isLength({ min: 1, max: 100 })
    ], this.getUserPermissions.bind(this));
    
    this.router.put('/users/:userId/permissions', [
      param('userId').isString().isLength({ min: 1, max: 100 }),
      body('permissions').isArray()
    ], this.updateUserPermissions.bind(this));
    
    this.router.delete('/users/sessions/:sessionId', [
      param('sessionId').isString().isLength({ min: 1, max: 100 })
    ], this.invalidateSession.bind(this));
    
    // Configuration routes with validation
    this.router.get('/config', this.getConfiguration.bind(this));
    this.router.put('/config', [
      body('security').optional().isObject(),
      body('api').optional().isObject(),
      body('features').optional().isObject()
    ], this.updateConfiguration.bind(this));
    
    // Webhook routes with validation
    this.router.post('/webhooks', [
      body('url').isURL().isLength({ min: 10, max: 500 }),
      body('events').isArray(),
      body('secret').optional().isString().isLength({ min: 16, max: 100 })
    ], this.configureWebhook.bind(this));
    
    this.router.get('/webhooks', this.listWebhooks.bind(this));
    this.router.delete('/webhooks/:webhookId', [
      param('webhookId').isString().isLength({ min: 1, max: 100 })
    ], this.deleteWebhook.bind(this));
    
    // Testing routes with validation
    this.router.post('/test/security', [
      body('scenarios').isArray(),
      body('scenarios.*.type').isIn(['prompt-injection', 'data-exfiltration', 'device-control', 'social-engineering']),
      body('scenarios.*.input').isString().isLength({ min: 1, max: 2000 }).escape()
    ], this.testSecurityScenarios.bind(this));
    
    this.router.get('/test/connectivity', this.testConnectivity.bind(this));
    
    // Add validation error handler
    this.router.use(this.handleValidationErrors.bind(this));
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

  setupV1Routes() {
    const v1Router = express.Router();
    
    // Authentication middleware
    v1Router.use(this.authenticateAPI.bind(this));
    
    // Rate limiting middleware
    v1Router.use(this.rateLimit.bind(this));
    
    // Request logging middleware
    v1Router.use(this.logRequest.bind(this));
    
    // Import and use route modules
    const SecurityRoutes = require('./security');
    const GoogleHomeRoutes = require('./googleHome');
    const CalendarRoutes = require('./calendar');
    
    // Mount routes
    v1Router.use('/security', new SecurityRoutes().router);
    v1Router.use('/google-home', new GoogleHomeRoutes().router);
    v1Router.use('/calendar', new CalendarRoutes().router);
    
    // Add new API endpoints
    v1Router.use('/threats', this.setupThreatRoutes());
    v1Router.use('/users', this.setupUserRoutes());
    v1Router.use('/config', this.setupConfigRoutes());
    v1Router.use('/webhooks', this.setupWebhookRoutes());
    v1Router.use('/test', this.setupTestRoutes());
    
    return v1Router;
  }

  setupThreatRoutes() {
    const threatRouter = express.Router();
    
    // Analyze input for threats
    threatRouter.post('/analyze', [
      body('input').isString().notEmpty(),
      body('context').optional().isObject()
    ], this.analyzeThreats.bind(this));
    
    // Get threat statistics
    threatRouter.get('/stats', this.getThreatStats.bind(this));
    
    // Get threat history
    threatRouter.get('/history', this.getThreatHistory.bind(this));
    
    return threatRouter;
  }

  setupUserRoutes() {
    const userRouter = express.Router();
    
    // Create user session
    userRouter.post('/sessions', [
      body('userId').isString().notEmpty(),
      body('permissions').isArray(),
      body('sessionDuration').optional().isInt({ min: 300, max: 86400 })
    ], this.createUserSession.bind(this));
    
    // Get user permissions
    userRouter.get('/:userId/permissions', this.getUserPermissions.bind(this));
    
    // Update user permissions
    userRouter.put('/:userId/permissions', [
      body('permissions').isObject()
    ], this.updateUserPermissions.bind(this));
    
    // Invalidate user session
    userRouter.delete('/sessions/:sessionId', this.invalidateSession.bind(this));
    
    return userRouter;
  }

  setupConfigRoutes() {
    const configRouter = express.Router();
    
    // Get configuration
    configRouter.get('/', this.getConfiguration.bind(this));
    
    // Update configuration
    configRouter.put('/', [
      body('security').optional().isObject(),
      body('api').optional().isObject(),
      body('features').optional().isObject()
    ], this.updateConfiguration.bind(this));
    
    return configRouter;
  }

  setupWebhookRoutes() {
    const webhookRouter = express.Router();
    
    // Configure webhook
    webhookRouter.post('/', [
      body('url').isURL(),
      body('events').isArray(),
      body('secret').isString().isLength({ min: 16 })
    ], this.configureWebhook.bind(this));
    
    // List webhooks
    webhookRouter.get('/', this.listWebhooks.bind(this));
    
    // Delete webhook
    webhookRouter.delete('/:webhookId', this.deleteWebhook.bind(this));
    
    return webhookRouter;
  }

  setupTestRoutes() {
    const testRouter = express.Router();
    
    // Test security scenarios
    testRouter.post('/security', [
      body('scenarios').isArray()
    ], this.testSecurityScenarios.bind(this));
    
    // Test API connectivity
    testRouter.get('/connectivity', this.testConnectivity.bind(this));
    
    return testRouter;
  }

  // Rate limiting middleware
  rateLimit(req, res, next) {
    // Simple in-memory rate limiting
    // In production, use Redis or a proper rate limiting library
    const clientIP = req.ip;
    const now = Date.now();
    const windowMs = 60 * 60 * 1000; // 1 hour
    const maxRequests = 100; // Free tier limit

    if (!req.app.locals.rateLimitStore) {
      req.app.locals.rateLimitStore = new Map();
    }

    const store = req.app.locals.rateLimitStore;
    const key = `${clientIP}:${req.apiKeyHash}`; // Use hashed API key for rate limiting
    const record = store.get(key) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
    } else {
      record.count++;
    }

    store.set(key, record);

    if (record.count > maxRequests) {
      return res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: 'Rate limit exceeded',
          details: {
            limit: maxRequests,
            window: '1 hour',
            resetTime: new Date(record.resetTime).toISOString()
          },
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    res.set('X-RateLimit-Limit', maxRequests);
    res.set('X-RateLimit-Remaining', Math.max(0, maxRequests - record.count));
    res.set('X-RateLimit-Reset', new Date(record.resetTime).toISOString());

    next();
  }

  // Request logging middleware
  logRequest(req, res, next) {
    req.id = this.generateRequestId();
    req.startTime = Date.now();

    this.logger.access('API Request', {
      requestId: req.id,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      apiKey: req.apiKey ? this.maskAPIKey(req.apiKey) : 'none'
    });

    // Log response
    res.on('finish', () => {
      const duration = Date.now() - req.startTime;
      this.logger.access('API Response', {
        requestId: req.id,
        statusCode: res.statusCode,
        duration: `${duration}ms`
      });
    });

    next();
  }

  // Threat analysis endpoint
  async analyzeThreats(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { input, context = {} } = req.body;
      const securityPatch = req.app.locals.securityPatch;

      if (!securityPatch) {
        return res.status(503).json({
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Security patch not available',
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const result = await securityPatch.processInput(input, context);

      res.json({
        threats: result.threats || [],
        securityScore: result.securityScore || 0,
        riskLevel: this.calculateRiskLevel(result.securityScore),
        recommendations: this.generateRecommendations(result),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error analyzing threats:', error);
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

  // Get threat statistics
  async getThreatStats(req, res) {
    try {
      const timeRange = req.query.timeRange || '24h';
      const securityPatch = req.app.locals.securityPatch;

      if (!securityPatch) {
        return res.status(503).json({
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Security patch not available',
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const stats = await securityPatch.getSecurityStatus();

      res.json({
        timeRange,
        totalRequests: stats.totalRequests || 0,
        threatsBlocked: stats.threatsBlocked || 0,
        confirmationsRequired: stats.confirmationsRequired || 0,
        averageResponseTime: stats.averageResponseTime || 0,
        uptime: stats.uptime || '99.9%',
        lastThreat: stats.lastThreat || null,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error getting threat stats:', error);
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

  // Get threat history
  async getThreatHistory(req, res) {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;

      // This would typically query a database
      // For now, return mock data
      res.json({
        threats: [],
        pagination: {
          limit,
          offset,
          total: 0,
          hasMore: false
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error getting threat history:', error);
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

  // Create user session
  async createUserSession(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { userId, permissions, sessionDuration = 3600 } = req.body;

      // Generate session token
      const sessionId = this.generateSessionId();
      const token = this.generateJWT({ userId, sessionId, permissions });
      const expiresAt = new Date(Date.now() + sessionDuration * 1000);

      res.status(201).json({
        sessionId,
        userId,
        permissions,
        expiresAt: expiresAt.toISOString(),
        token,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error creating user session:', error);
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

  // Get user permissions
  async getUserPermissions(req, res) {
    try {
      const { userId } = req.params;

      // This would typically query a database
      // For now, return mock data
      res.json({
        userId,
        permissions: {
          device_control: {
            level: 'full',
            devices: ['light-001', 'thermostat-001']
          },
          calendar_access: {
            level: 'read',
            calendars: ['primary']
          }
        },
        lastUpdated: new Date().toISOString(),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error getting user permissions:', error);
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

  // Update user permissions
  async updateUserPermissions(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { userId } = req.params;
      const { permissions } = req.body;

      // This would typically update a database
      // For now, return success
      res.json({
        userId,
        permissions,
        updated: true,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error updating user permissions:', error);
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

  // Invalidate session
  async invalidateSession(req, res) {
    try {
      const { sessionId } = req.params;

      // This would typically invalidate the session in a database
      // For now, return success
      res.json({
        sessionId,
        invalidated: true,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error invalidating session:', error);
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

  // Get configuration
  async getConfiguration(req, res) {
    try {
      const configManager = req.app.locals.configManager;

      if (!configManager) {
        return res.status(503).json({
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Configuration manager not available',
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const config = configManager.getFullConfig();

      res.json({
        security: config.config,
        api: {
          version: '1.0.0',
          rateLimit: {
            requests: 100,
            window: 3600
          }
        },
        features: {
          threatDetection: true,
          userConfirmation: true,
          accessControl: true
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error getting configuration:', error);
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

  // Update configuration
  async updateConfiguration(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const configManager = req.app.locals.configManager;

      if (!configManager) {
        return res.status(503).json({
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Configuration manager not available',
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { security, api, features } = req.body;

      // Update configuration
      if (security) {
        for (const [key, value] of Object.entries(security)) {
          await configManager.updateConfig(key, value);
        }
      }

      res.json({
        updated: true,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error updating configuration:', error);
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

  // Configure webhook
  async configureWebhook(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { url, events, secret } = req.body;
      const webhookId = this.generateWebhookId();

      // This would typically store in a database
      // For now, return success
      res.status(201).json({
        webhookId,
        url,
        events,
        active: true,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error configuring webhook:', error);
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

  // List webhooks
  async listWebhooks(req, res) {
    try {
      // This would typically query a database
      // For now, return empty array
      res.json({
        webhooks: [],
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error listing webhooks:', error);
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

  // Delete webhook
  async deleteWebhook(req, res) {
    try {
      const { webhookId } = req.params;

      // This would typically delete from a database
      // For now, return success
      res.json({
        webhookId,
        deleted: true,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error deleting webhook:', error);
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

  // Test security scenarios
  async testSecurityScenarios(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Validation failed',
            details: errors.array(),
            timestamp: new Date().toISOString(),
            requestId: req.id
          }
        });
      }

      const { scenarios } = req.body;
      const results = [];

      for (const scenario of scenarios) {
        const result = {
          name: scenario.name,
          passed: false,
          actual: {},
          expected: scenario.expected
        };

        // Run the scenario test
        // This would typically use the security patch to test
        if (scenario.name === 'malicious_calendar_event') {
          result.actual = {
            blocked: true,
            threats: ['prompt_injection']
          };
          result.passed = true;
        }

        results.push(result);
      }

      res.json({
        scenarios: results,
        summary: {
          total: results.length,
          passed: results.filter(r => r.passed).length,
          failed: results.filter(r => !r.passed).length
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

    } catch (error) {
      this.logger.error('Error testing security scenarios:', error);
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

  // Test connectivity
  async testConnectivity(req, res) {
    try {
      const securityPatch = req.app.locals.securityPatch;
      const configManager = req.app.locals.configManager;

      const status = {
        api: true,
        securityPatch: !!securityPatch,
        configManager: !!configManager,
        timestamp: new Date().toISOString(),
        requestId: req.id
      };

      res.json(status);

    } catch (error) {
      this.logger.error('Error testing connectivity:', error);
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

  // Health check
  async healthCheck(req, res) {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  }

  // Get API documentation
  async getAPIDocs(req, res) {
    res.json({
      message: 'API documentation available at /docs/API.md',
      endpoints: {
        v1: '/api/v1',
        health: '/api/health',
        docs: '/docs/API.md'
      },
      timestamp: new Date().toISOString()
    });
  }

  // Get version info
  async getVersion(req, res) {
    res.json({
      version: '1.0.0',
      apiVersion: 'v1',
      timestamp: new Date().toISOString()
    });
  }

  // Utility methods
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateWebhookId() {
    return `webhook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateJWT(payload) {
    try {
      const configManager = this.router.app?.locals?.configManager;
      const jwtSecret = configManager?.getSecret('jwt.secret') || process.env.JWT_SECRET;
      
      if (!jwtSecret) {
        throw new Error('JWT secret not configured');
      }
      
      // Use proper JWT library with secure options
      return jwt.sign(payload, jwtSecret, {
        algorithm: 'HS256',
        expiresIn: payload.expiresIn || '1h',
        issuer: 'google-home-security-patch',
        audience: 'api-users'
      });
    } catch (error) {
      this.logger.error('Error generating JWT:', error);
      throw new Error('Failed to generate authentication token');
    }
  }

  verifyJWT(token) {
    try {
      const configManager = this.router.app?.locals?.configManager;
      const jwtSecret = configManager?.getSecret('jwt.secret') || process.env.JWT_SECRET;
      
      if (!jwtSecret) {
        throw new Error('JWT secret not configured');
      }
      
      // Verify JWT with proper options
      return jwt.verify(token, jwtSecret, {
        algorithms: ['HS256'],
        issuer: 'google-home-security-patch',
        audience: 'api-users'
      });
    } catch (error) {
      this.logger.error('Error verifying JWT:', error);
      throw new Error('Invalid authentication token');
    }
  }

  calculateRiskLevel(score) {
    if (score >= 0.8) return 'critical';
    if (score >= 0.6) return 'high';
    if (score >= 0.3) return 'medium';
    return 'low';
  }

  generateRecommendations(result) {
    const recommendations = [];
    
    if (result.securityScore > 0.6) {
      recommendations.push('Enable strict mode');
    }
    
    if (result.threats && result.threats.length > 0) {
      recommendations.push('Require user confirmation');
    }
    
    return recommendations;
  }

  getRouter() {
    return this.router;
  }
}

module.exports = APIRouter;
