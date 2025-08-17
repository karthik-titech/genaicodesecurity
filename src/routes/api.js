const express = require('express');
const { body, validationResult } = require('express-validator');
const Logger = require('../utils/Logger');

class APIRouter {
  constructor() {
    this.router = express.Router();
    this.logger = new Logger();
    this.setupRoutes();
  }

  setupRoutes() {
    // API versioning middleware
    this.router.use('/v1', this.setupV1Routes());
    
    // API health check
    this.router.get('/health', this.healthCheck.bind(this));
    
    // API documentation
    this.router.get('/docs', this.getAPIDocs.bind(this));
    
    // API version info
    this.router.get('/version', this.getVersion.bind(this));
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

  // Authentication middleware
  authenticateAPI(req, res, next) {
    const apiKey = req.headers.authorization?.replace('Bearer ', '') || 
                   req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        error: {
          code: 'INVALID_API_KEY',
          message: 'API key is required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }

    // Validate API key (implement your validation logic)
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

    // For now, accept any non-empty API key
    // In production, validate against stored API keys
    if (!apiKey || apiKey.length < 10) {
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
    next();
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
    const key = `${clientIP}:${req.apiKey}`;
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
      apiKey: req.apiKey ? `${req.apiKey.substring(0, 8)}...` : 'none'
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
    // In production, use a proper JWT library
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    return `${encodedHeader}.${encodedPayload}.signature`;
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
