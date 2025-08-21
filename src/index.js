const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const SecurityPatch = require('./security/SecurityPatch');
const ConfigManager = require('./config/ConfigManager');
const SecurityMiddleware = require('./middleware/SecurityMiddleware');
const Logger = require('./utils/Logger');

class GoogleHomeSecurityPatch {
  constructor() {
    this.app = express();
    this.configManager = new ConfigManager();
    this.securityPatch = new SecurityPatch();
    this.securityMiddleware = new SecurityMiddleware();
    this.logger = new Logger();
    
    this.initializeSecurityLayers();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupSecurityPatch();
  }

  async initializeSecurityLayers() {
    try {
      // Initialize configuration manager first
      await this.configManager.initialize();
      
      // Initialize security patch with configuration
      await this.securityPatch.initialize(this.configManager);
      
      this.logger.info('Security layers initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize security layers:', error);
      throw error;
    }
  }

  setupMiddleware() {
    // Enhanced security middleware
    const securityMiddleware = this.securityMiddleware.getMiddleware();
    
    // Security headers
    this.app.use(securityMiddleware.securityHeaders);
    
    // Request size limiting
    this.app.use(securityMiddleware.requestSizeLimit);
    
    // SQL injection protection
    this.app.use(securityMiddleware.sqlInjectionProtection);
    
    // XSS protection
    this.app.use(securityMiddleware.xssProtection);
    
    // Enhanced rate limiting
    this.app.use(securityMiddleware.advancedRateLimit);
    
    // Security logging
    this.app.use(securityMiddleware.securityLogging);

    // Additional security with helmet
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"]
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      noSniff: true,
      xssFilter: true,
      frameguard: { action: 'deny' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
    }));

    // CORS configuration with enhanced security
    this.app.use(cors({
      origin: (origin, callback) => {
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          this.logger.security('CORS violation attempt', { origin });
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-CSRF-Token', 'X-Session-ID'],
      exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
      maxAge: 86400 // 24 hours
    }));

    // Body parsing with size limits
    this.app.use(express.json({ 
      limit: '10mb',
      verify: (req, res, buf) => {
        // Store raw body for signature verification if needed
        req.rawBody = buf;
      }
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb',
      parameterLimit: 1000
    }));

    // Trust proxy for accurate IP addresses
    this.app.set('trust proxy', 1);
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({ 
        status: 'healthy', 
        security: 'active',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        uptime: process.uptime()
      });
    });

    // API routes (v1) with enhanced security
    const apiRouter = new (require('./routes/api'))();
    this.app.use('/api/v1', apiRouter.getRouter());
    
    // Legacy routes (for backward compatibility) with security middleware
    this.app.use('/api/security', require('./routes/security'));
    this.app.use('/api/google-home', require('./routes/googleHome'));
    this.app.use('/api/calendar', require('./routes/calendar'));
    
    // Error handling middleware with security logging
    this.app.use((err, req, res, next) => {
      this.logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
        timestamp: new Date().toISOString()
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      this.logger.warn('404 Not Found', {
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      res.status(404).json({ 
        error: 'Endpoint not found',
        timestamp: new Date().toISOString()
      });
    });
  }

  setupSecurityPatch() {
    // Make security patch and config manager available to routes
    this.app.locals.securityPatch = this.securityPatch;
    this.app.locals.configManager = this.configManager;
    this.app.locals.securityMiddleware = this.securityMiddleware;
  }

  async start(port = process.env.PORT || 3000) {
    try {
      await this.initializeSecurityLayers();
      
      const server = this.app.listen(port, () => {
        this.logger.info(`Google Home Security Patch running on port ${port}`);
        this.logger.info('Security layers: ACTIVE');
        this.logger.info('Threat detection: ENABLED');
        this.logger.info('Input sanitization: ENABLED');
        this.logger.info('Context protection: ENABLED');
        this.logger.info('Tool execution guard: ENABLED');
        this.logger.info('User confirmation system: ENABLED');
        this.logger.info('Access control: ENABLED');
        this.logger.info('Configuration management: ENABLED');
        this.logger.info('Enhanced security middleware: ENABLED');
        this.logger.info('CSRF protection: ENABLED');
        this.logger.info('SQL injection protection: ENABLED');
        this.logger.info('XSS protection: ENABLED');
        this.logger.info('Advanced rate limiting: ENABLED');
      });

      // Graceful shutdown
      process.on('SIGTERM', () => {
        this.logger.info('SIGTERM received, shutting down gracefully');
        server.close(() => {
          this.logger.info('Process terminated');
          process.exit(0);
        });
      });

      process.on('SIGINT', () => {
        this.logger.info('SIGINT received, shutting down gracefully');
        server.close(() => {
          this.logger.info('Process terminated');
          process.exit(0);
        });
      });

    } catch (error) {
      this.logger.error('Failed to start security patch:', error);
      process.exit(1);
    }
  }
}

// Start the security patch
const securityPatch = new GoogleHomeSecurityPatch();
securityPatch.start();

module.exports = GoogleHomeSecurityPatch;
