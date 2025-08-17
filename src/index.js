const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const SecurityPatch = require('./security/SecurityPatch');
const ConfigManager = require('./config/ConfigManager');
const Logger = require('./utils/Logger');

class GoogleHomeSecurityPatch {
  constructor() {
    this.app = express();
    this.configManager = new ConfigManager();
    this.securityPatch = new SecurityPatch();
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
    // Security middleware
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
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use(limiter);

    // CORS configuration
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization']
    }));

    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({ 
        status: 'healthy', 
        security: 'active',
        timestamp: new Date().toISOString()
      });
    });

    // API routes (v1)
    const apiRouter = new (require('./routes/api'))();
    this.app.use('/api', apiRouter.getRouter());
    
    // Legacy routes (for backward compatibility)
    this.app.use('/api/security', require('./routes/security'));
    this.app.use('/api/google-home', require('./routes/googleHome'));
    this.app.use('/api/calendar', require('./routes/calendar'));
    
    // Error handling middleware
    this.app.use((err, req, res, next) => {
      this.logger.error('Unhandled error:', err);
      res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({ error: 'Endpoint not found' });
    });
  }

  setupSecurityPatch() {
    // Make security patch and config manager available to routes
    this.app.locals.securityPatch = this.securityPatch;
    this.app.locals.configManager = this.configManager;
  }

  async start(port = process.env.PORT || 3000) {
    try {
      await this.initializeSecurityLayers();
      this.app.listen(port, () => {
        this.logger.info(`Google Home Security Patch running on port ${port}`);
        this.logger.info('Security layers: ACTIVE');
        this.logger.info('Threat detection: ENABLED');
        this.logger.info('Input sanitization: ENABLED');
        this.logger.info('Context protection: ENABLED');
        this.logger.info('Tool execution guard: ENABLED');
        this.logger.info('User confirmation system: ENABLED');
        this.logger.info('Access control: ENABLED');
        this.logger.info('Configuration management: ENABLED');
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
