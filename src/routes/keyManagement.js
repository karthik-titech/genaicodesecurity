const express = require('express');
const router = express.Router();
const { body, validationResult, param, query } = require('express-validator');
const Logger = require('../utils/Logger');

class KeyManagementRoutes {
  constructor() {
    this.logger = new Logger();
    this.setupRoutes();
  }

  setupRoutes() {
    // Key Management Routes
    router.get('/keys', [
      query('type').optional().isIn(['encryption', 'signing', 'session', 'api']),
      query('status').optional().isIn(['active', 'expired', 'all']),
      query('limit').optional().isInt({ min: 1, max: 100 }),
      query('offset').optional().isInt({ min: 0 })
    ], this.getKeys.bind(this));
    
    router.post('/keys/generate', [
      body('type').isIn(['encryption', 'signing', 'session', 'api']),
      body('metadata').optional().isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.generateKey.bind(this));
    
    router.get('/keys/:keyId', [
      param('keyId').isString().isLength({ min: 1, max: 200 })
    ], this.getKey.bind(this));
    
    router.post('/keys/:keyId/rotate', [
      param('keyId').isString().isLength({ min: 1, max: 200 }),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('reason').optional().isString().isLength({ min: 1, max: 500 })
    ], this.rotateKey.bind(this));
    
    router.delete('/keys/:keyId', [
      param('keyId').isString().isLength({ min: 1, max: 200 }),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('reason').optional().isString().isLength({ min: 1, max: 500 })
    ], this.removeKey.bind(this));
    
    router.get('/keys/statistics', this.getKeyStatistics.bind(this));
    
    // Workflow Handle Routes
    router.get('/handles', [
      query('type').optional().isIn(['session', 'workflow', 'api', 'device']),
      query('status').optional().isIn(['active', 'expired', 'all']),
      query('limit').optional().isInt({ min: 1, max: 100 }),
      query('offset').optional().isInt({ min: 0 })
    ], this.getHandles.bind(this));
    
    router.post('/handles/generate', [
      body('type').isIn(['session', 'workflow', 'api', 'device']),
      body('context').optional().isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.generateHandle.bind(this));
    
    router.post('/handles/validate', [
      body('handleId').isString().isLength({ min: 1, max: 200 }),
      body('context').optional().isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.validateHandle.bind(this));
    
    router.post('/handles/:handleId/rotate', [
      param('handleId').isString().isLength({ min: 1, max: 200 }),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('reason').optional().isString().isLength({ min: 1, max: 500 })
    ], this.rotateHandle.bind(this));
    
    router.delete('/handles/:handleId', [
      param('handleId').isString().isLength({ min: 1, max: 200 }),
      body('userId').isString().isLength({ min: 1, max: 100 }),
      body('reason').optional().isString().isLength({ min: 1, max: 500 })
    ], this.removeHandle.bind(this));
    
    router.get('/handles/statistics', this.getHandleStatistics.bind(this));
    
    // Health and Monitoring Routes
    router.get('/health', this.getHealthStatus.bind(this));
    router.get('/health/keys', this.getKeyHealth.bind(this));
    router.get('/health/handles', this.getHandleHealth.bind(this));
    
    // Configuration Routes
    router.get('/config', this.getConfiguration.bind(this));
    router.put('/config', [
      body('keyTypes').optional().isObject(),
      body('handleTypes').optional().isObject(),
      body('securityPolicies').optional().isObject(),
      body('userId').isString().isLength({ min: 1, max: 100 })
    ], this.updateConfiguration.bind(this));
    
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

  // Key Management Methods
  async getKeys(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { type, status, limit = 50, offset = 0 } = req.query;
      
      let keys = [];
      
      if (type) {
        keys = keyManagementSystem.getActiveKeysByType(type);
      } else {
        // Get all active keys
        for (const [keyId, keyInfo] of keyManagementSystem.activeKeys) {
          keys.push(keyInfo);
        }
      }
      
      // Filter by status
      if (status && status !== 'all') {
        const now = Date.now();
        keys = keys.filter(key => {
          if (status === 'active') {
            return key.isActive && key.expiresAt > now;
          } else if (status === 'expired') {
            return !key.isActive || key.expiresAt <= now;
          }
          return true;
        });
      }
      
      // Apply pagination
      const paginatedKeys = keys.slice(offset, offset + parseInt(limit));
      
      this.logger.access('Keys retrieved', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        type,
        status,
        count: paginatedKeys.length,
        total: keys.length,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        keys: paginatedKeys,
        pagination: {
          total: keys.length,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: offset + parseInt(limit) < keys.length
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting keys:', {
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

  async generateKey(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { type, metadata, userId } = req.body;
      
      const keyInfo = await keyManagementSystem.generateKey(type, {
        metadata: {
          ...metadata,
          generatedBy: userId,
          generatedAt: new Date().toISOString()
        }
      });

      this.logger.audit('Key generated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        keyType: type,
        keyId: keyInfo.id,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        key: keyInfo,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error generating key:', {
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

  async getKey(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { keyId } = req.params;
      
      const keyData = await keyManagementSystem.getKey(keyId);

      this.logger.access('Key retrieved', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        keyId,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        key: {
          id: keyData.keyInfo.id,
          type: keyData.keyInfo.type,
          algorithm: keyData.keyInfo.algorithm,
          createdAt: keyData.keyInfo.createdAt,
          expiresAt: keyData.keyInfo.expiresAt,
          isActive: keyData.keyInfo.isActive,
          usageCount: keyData.keyInfo.usageCount,
          lastUsed: keyData.keyInfo.lastUsed,
          metadata: keyData.keyInfo.metadata
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting key:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        keyId: req.params.keyId,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      res.status(404).json({ 
        error: {
          code: 'KEY_NOT_FOUND',
          message: 'Key not found or inactive',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
    }
  }

  async rotateKey(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { keyId } = req.params;
      const { userId, reason } = req.body;
      
      const newKeyInfo = await keyManagementSystem.rotateKey(keyId);

      this.logger.audit('Key rotated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        oldKeyId: keyId,
        newKeyId: newKeyInfo.id,
        reason: reason || 'manual_rotation',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        oldKeyId: keyId,
        newKey: newKeyInfo,
        reason: reason || 'manual_rotation',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error rotating key:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        keyId: req.params.keyId,
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

  async removeKey(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { keyId } = req.params;
      const { userId, reason } = req.body;
      
      await keyManagementSystem.removeKey(keyId);

      this.logger.audit('Key removed', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        keyId,
        reason: reason || 'manual_removal',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        message: 'Key removed successfully',
        keyId,
        reason: reason || 'manual_removal',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error removing key:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        keyId: req.params.keyId,
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

  async getKeyStatistics(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const stats = await keyManagementSystem.getKeyStatistics();

      this.logger.access('Key statistics retrieved', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        statistics: stats,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting key statistics:', {
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

  // Workflow Handle Methods
  async getHandles(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { type, status, limit = 50, offset = 0 } = req.query;
      
      let handles = [];
      
      if (type) {
        handles = workflowHandleRotation.getActiveHandlesByType(type);
      } else {
        // Get all active handles
        for (const [handleId, handleInfo] of workflowHandleRotation.activeHandles) {
          handles.push(handleInfo);
        }
      }
      
      // Filter by status
      if (status && status !== 'all') {
        const now = Date.now();
        handles = handles.filter(handle => {
          if (status === 'active') {
            return handle.isActive && handle.expiresAt > now;
          } else if (status === 'expired') {
            return !handle.isActive || handle.expiresAt <= now;
          }
          return true;
        });
      }
      
      // Apply pagination
      const paginatedHandles = handles.slice(offset, offset + parseInt(limit));
      
      this.logger.access('Handles retrieved', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        type,
        status,
        count: paginatedHandles.length,
        total: handles.length,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        handles: paginatedHandles,
        pagination: {
          total: handles.length,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: offset + parseInt(limit) < handles.length
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting handles:', {
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

  async generateHandle(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { type, context, userId } = req.body;
      
      const handleData = await workflowHandleRotation.generateHandle(type, {
        ...context,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        generatedAt: new Date().toISOString()
      });

      this.logger.audit('Handle generated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        handleType: type,
        handleId: handleData.handleId,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        handle: {
          id: handleData.handleId,
          data: handleData.handleData,
          info: handleData.handleInfo
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error generating handle:', {
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

  async validateHandle(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { handleId, context, userId } = req.body;
      
      const validationResult = await workflowHandleRotation.validateHandle(handleId, {
        ...context,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId
      });

      this.logger.access('Handle validated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        handleId,
        valid: validationResult.valid,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        validation: validationResult,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error validating handle:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        handleId: req.body.handleId,
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

  async rotateHandle(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { handleId } = req.params;
      const { userId, reason } = req.body;
      
      const newHandle = await workflowHandleRotation.rotateHandle(handleId);

      this.logger.audit('Handle rotated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        oldHandleId: handleId,
        newHandleId: newHandle.handleId,
        reason: reason || 'manual_rotation',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        oldHandleId: handleId,
        newHandle: newHandle,
        reason: reason || 'manual_rotation',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error rotating handle:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        handleId: req.params.handleId,
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

  async removeHandle(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const { handleId } = req.params;
      const { userId, reason } = req.body;
      
      await workflowHandleRotation.removeHandle(handleId);

      this.logger.audit('Handle removed', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        handleId,
        reason: reason || 'manual_removal',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        message: 'Handle removed successfully',
        handleId,
        reason: reason || 'manual_removal',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error removing handle:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        handleId: req.params.handleId,
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

  async getHandleStatistics(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      const stats = await workflowHandleRotation.getHandleStatistics();

      this.logger.access('Handle statistics retrieved', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        statistics: stats,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting handle statistics:', {
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

  // Health and Monitoring Methods
  async getHealthStatus(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      
      const health = {
        keyManagement: {
          active: keyManagementSystem ? keyManagementSystem.isActive : false,
          totalKeys: keyManagementSystem ? keyManagementSystem.activeKeys.size : 0
        },
        workflowHandles: {
          active: workflowHandleRotation ? workflowHandleRotation.isActive : false,
          totalHandles: workflowHandleRotation ? workflowHandleRotation.activeHandles.size : 0
        },
        timestamp: new Date().toISOString()
      };

      res.json({
        success: true,
        health: health,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting health status:', error);
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

  async getKeyHealth(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      if (!keyManagementSystem) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Key Management System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      // This would call the checkKeyHealth method
      const health = {
        totalKeys: keyManagementSystem.activeKeys.size,
        activeKeys: 0,
        expiringKeys: 0,
        expiredKeys: 0,
        rotationQueue: keyManagementSystem.rotationQueue.length
      };

      const now = Date.now();
      for (const [keyId, keyInfo] of keyManagementSystem.activeKeys) {
        if (keyInfo.isActive) {
          health.activeKeys++;
          if (keyInfo.expiresAt && (keyInfo.expiresAt - now) <= keyInfo.warningThreshold) {
            health.expiringKeys++;
          }
        } else {
          health.expiredKeys++;
        }
      }

      res.json({
        success: true,
        health: health,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting key health:', error);
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

  async getHandleHealth(req, res) {
    try {
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      if (!workflowHandleRotation) {
        return res.status(503).json({ 
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Workflow Handle Rotation System not available',
            timestamp: new Date().toISOString()
          }
        });
      }

      // This would call the checkHandleHealth method
      const health = {
        totalHandles: workflowHandleRotation.activeHandles.size,
        activeHandles: 0,
        expiringHandles: 0,
        expiredHandles: 0,
        rotationQueue: workflowHandleRotation.rotationQueue.length
      };

      const now = Date.now();
      for (const [handleId, handleInfo] of workflowHandleRotation.activeHandles) {
        if (handleInfo.isActive) {
          health.activeHandles++;
          if (handleInfo.expiresAt && (handleInfo.expiresAt - now) <= handleInfo.warningThreshold) {
            health.expiringHandles++;
          }
        } else {
          health.expiredHandles++;
        }
      }

      res.json({
        success: true,
        health: health,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error getting handle health:', error);
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

  // Configuration Methods
  async getConfiguration(req, res) {
    try {
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      
      const config = {
        keyTypes: keyManagementSystem ? keyManagementSystem.keyTypes : {},
        handleTypes: workflowHandleRotation ? workflowHandleRotation.handleTypes : {},
        securityPolicies: workflowHandleRotation ? workflowHandleRotation.securityPolicies : {},
        timestamp: new Date().toISOString()
      };

      res.json({
        success: true,
        configuration: config,
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

  async updateConfiguration(req, res) {
    try {
      const { keyTypes, handleTypes, securityPolicies, userId } = req.body;
      
      const keyManagementSystem = req.app.locals.keyManagementSystem;
      const workflowHandleRotation = req.app.locals.workflowHandleRotation;
      
      // Update key types configuration
      if (keyTypes && keyManagementSystem) {
        Object.assign(keyManagementSystem.keyTypes, keyTypes);
      }
      
      // Update handle types configuration
      if (handleTypes && workflowHandleRotation) {
        Object.assign(workflowHandleRotation.handleTypes, handleTypes);
      }
      
      // Update security policies
      if (securityPolicies && workflowHandleRotation) {
        Object.assign(workflowHandleRotation.securityPolicies, securityPolicies);
      }

      this.logger.audit('Configuration updated', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId,
        changes: { keyTypes, handleTypes, securityPolicies },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });

      res.json({
        success: true,
        message: 'Configuration updated successfully',
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Error updating configuration:', {
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
}

// Initialize routes
const keyManagementRoutes = new KeyManagementRoutes();

module.exports = router;
