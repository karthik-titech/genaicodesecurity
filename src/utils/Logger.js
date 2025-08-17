const winston = require('winston');
const path = require('path');

class Logger {
  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'google-home-security-patch' },
      transports: [
        // Console transport
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        
        // File transport for all logs
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/security-patch.log'),
          maxsize: 5242880, // 5MB
          maxFiles: 5,
          tailable: true
        }),
        
        // File transport for error logs
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/security-patch-error.log'),
          level: 'error',
          maxsize: 5242880, // 5MB
          maxFiles: 5,
          tailable: true
        }),
        
        // File transport for security events
        new winston.transports.File({
          filename: path.join(__dirname, '../../logs/security-events.log'),
          level: 'warn',
          maxsize: 5242880, // 5MB
          maxFiles: 10,
          tailable: true
        })
      ]
    });

    // Create logs directory if it doesn't exist
    const fs = require('fs');
    const logsDir = path.join(__dirname, '../../logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
  }

  info(message, meta = {}) {
    this.logger.info(message, {
      ...meta,
      timestamp: new Date().toISOString()
    });
  }

  warn(message, meta = {}) {
    this.logger.warn(message, {
      ...meta,
      timestamp: new Date().toISOString()
    });
  }

  error(message, meta = {}) {
    this.logger.error(message, {
      ...meta,
      timestamp: new Date().toISOString()
    });
  }

  debug(message, meta = {}) {
    this.logger.debug(message, {
      ...meta,
      timestamp: new Date().toISOString()
    });
  }

  security(message, meta = {}) {
    this.logger.warn(`SECURITY: ${message}`, {
      ...meta,
      timestamp: new Date().toISOString(),
      securityEvent: true
    });
  }

  threat(message, meta = {}) {
    this.logger.error(`THREAT: ${message}`, {
      ...meta,
      timestamp: new Date().toISOString(),
      threatEvent: true
    });
  }

  access(message, meta = {}) {
    this.logger.info(`ACCESS: ${message}`, {
      ...meta,
      timestamp: new Date().toISOString(),
      accessEvent: true
    });
  }

  audit(message, meta = {}) {
    this.logger.info(`AUDIT: ${message}`, {
      ...meta,
      timestamp: new Date().toISOString(),
      auditEvent: true
    });
  }
}

module.exports = Logger;
