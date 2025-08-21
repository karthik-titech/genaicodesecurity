const crypto = require('crypto');
const Logger = require('../utils/Logger');

class SecurityMiddleware {
  constructor() {
    this.logger = new Logger();
    this.csrfTokens = new Map();
  }

  // CSRF Protection
  csrfProtection(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }

    const token = req.headers['x-csrf-token'] || req.body._csrf;
    const sessionId = req.headers['x-session-id'] || req.body.sessionId;

    if (!token || !sessionId) {
      return res.status(403).json({
        error: {
          code: 'CSRF_TOKEN_MISSING',
          message: 'CSRF token or session ID missing',
          timestamp: new Date().toISOString()
        }
      });
    }

    const expectedToken = this.csrfTokens.get(sessionId);
    if (!expectedToken || token !== expectedToken) {
      this.logger.security('CSRF token validation failed', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: sessionId.substring(0, 8) + '...'
      });

      return res.status(403).json({
        error: {
          code: 'CSRF_TOKEN_INVALID',
          message: 'Invalid CSRF token',
          timestamp: new Date().toISOString()
        }
      });
    }

    next();
  }

  // Generate CSRF token
  generateCSRFToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    this.csrfTokens.set(sessionId, token);
    
    // Clean up old tokens (older than 24 hours)
    setTimeout(() => {
      this.csrfTokens.delete(sessionId);
    }, 24 * 60 * 60 * 1000);

    return token;
  }

  // Request size limiting
  requestSizeLimit(req, res, next) {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxSize = 10 * 1024 * 1024; // 10MB

    if (contentLength > maxSize) {
      return res.status(413).json({
        error: {
          code: 'REQUEST_TOO_LARGE',
          message: 'Request body too large',
          maxSize: maxSize,
          timestamp: new Date().toISOString()
        }
      });
    }

    next();
  }

  // SQL Injection Protection
  sqlInjectionProtection(req, res, next) {
    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b)/i,
      /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
      /(\b(union|select)\b.*\bfrom\b)/i,
      /(\b(insert|update|delete)\b.*\bwhere\b)/i,
      /(\b(drop|create|alter)\b.*\b(table|database|user)\b)/i,
      /(\b(exec|execute)\b.*\bxp_|sp_)/i,
      /(\b(script)\b.*\bjavascript)/i
    ];

    const checkValue = (value) => {
      if (typeof value === 'string') {
        return sqlPatterns.some(pattern => pattern.test(value));
      } else if (typeof value === 'object' && value !== null) {
        return Object.values(value).some(checkValue);
      }
      return false;
    };

    const hasSQLInjection = checkValue(req.body) || checkValue(req.query) || checkValue(req.params);

    if (hasSQLInjection) {
      this.logger.security('SQL injection attempt detected', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        body: JSON.stringify(req.body).substring(0, 200),
        query: JSON.stringify(req.query).substring(0, 200)
      });

      return res.status(400).json({
        error: {
          code: 'SQL_INJECTION_DETECTED',
          message: 'Malicious input detected',
          timestamp: new Date().toISOString()
        }
      });
    }

    next();
  }

  // XSS Protection
  xssProtection(req, res, next) {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /data:text\/html/gi,
      /vbscript:/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi
    ];

    const checkValue = (value) => {
      if (typeof value === 'string') {
        return xssPatterns.some(pattern => pattern.test(value));
      } else if (typeof value === 'object' && value !== null) {
        return Object.values(value).some(checkValue);
      }
      return false;
    };

    const hasXSS = checkValue(req.body) || checkValue(req.query) || checkValue(req.params);

    if (hasXSS) {
      this.logger.security('XSS attempt detected', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        body: JSON.stringify(req.body).substring(0, 200),
        query: JSON.stringify(req.query).substring(0, 200)
      });

      return res.status(400).json({
        error: {
          code: 'XSS_DETECTED',
          message: 'Malicious input detected',
          timestamp: new Date().toISOString()
        }
      });
    }

    next();
  }

  // Rate limiting per IP and endpoint
  advancedRateLimit(req, res, next) {
    const clientIP = req.ip;
    const endpoint = req.path;
    const method = req.method;
    const key = `${clientIP}:${endpoint}:${method}`;

    if (!req.app.locals.advancedRateLimitStore) {
      req.app.locals.advancedRateLimitStore = new Map();
    }

    const store = req.app.locals.advancedRateLimitStore;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = this.getRateLimitForEndpoint(endpoint);

    const record = store.get(key) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
    } else {
      record.count++;
    }

    store.set(key, record);

    if (record.count > maxRequests) {
      this.logger.security('Rate limit exceeded', {
        ip: clientIP,
        endpoint,
        method,
        count: record.count,
        limit: maxRequests
      });

      return res.status(429).json({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests',
          details: {
            endpoint,
            limit: maxRequests,
            window: '15 minutes',
            resetTime: new Date(record.resetTime).toISOString()
          },
          timestamp: new Date().toISOString()
        }
      });
    }

    res.set('X-RateLimit-Limit', maxRequests);
    res.set('X-RateLimit-Remaining', Math.max(0, maxRequests - record.count));
    res.set('X-RateLimit-Reset', new Date(record.resetTime).toISOString());

    next();
  }

  // Get rate limit for specific endpoint
  getRateLimitForEndpoint(endpoint) {
    const limits = {
      '/api/v1/security/status': 1000,
      '/api/v1/security/stats': 100,
      '/api/v1/threats/analyze': 50,
      '/api/v1/google-home/process': 200,
      '/api/v1/calendar/process-event': 100,
      '/api/v1/users/sessions': 10,
      '/api/v1/config': 50,
      '/api/v1/webhooks': 20
    };

    return limits[endpoint] || 100; // Default limit
  }

  // Security headers
  securityHeaders(req, res, next) {
    // Content Security Policy
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "media-src 'self'",
      "object-src 'none'",
      "frame-src 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; '));

    // Other security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    next();
  }

  // Request logging with security events
  securityLogging(req, res, next) {
    const startTime = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const logData = {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        contentLength: req.headers['content-length'] || 0,
        timestamp: new Date().toISOString()
      };

      // Log security events
      if (res.statusCode >= 400) {
        this.logger.security('API Error', logData);
      } else if (duration > 5000) {
        this.logger.warn('Slow API request', logData);
      } else {
        this.logger.access('API Request', logData);
      }
    });

    next();
  }

  // Get all middleware functions
  getMiddleware() {
    return {
      securityHeaders: this.securityHeaders.bind(this),
      requestSizeLimit: this.requestSizeLimit.bind(this),
      sqlInjectionProtection: this.sqlInjectionProtection.bind(this),
      xssProtection: this.xssProtection.bind(this),
      advancedRateLimit: this.advancedRateLimit.bind(this),
      csrfProtection: this.csrfProtection.bind(this),
      securityLogging: this.securityLogging.bind(this)
    };
  }
}

module.exports = SecurityMiddleware;
