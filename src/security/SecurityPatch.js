const InputSanitizer = require('./InputSanitizer');
const ContextProtector = require('./ContextProtector');
const ToolExecutionGuard = require('./ToolExecutionGuard');
const UserConfirmationSystem = require('./UserConfirmationSystem');
const AccessControlManager = require('./AccessControlManager');
const ThreatDetector = require('./ThreatDetector');
const Logger = require('../utils/Logger');

class SecurityPatch {
  constructor() {
    this.logger = new Logger();
    this.securityLayers = {};
    this.isInitialized = false;
    this.configManager = null;
    this.securityConfig = {
      enableInputSanitization: true,
      enableContextProtection: true,
      enableToolExecutionGuard: true,
      enableUserConfirmation: true,
      enableAccessControl: true,
      enableThreatDetection: true,
      strictMode: false,
      maxContextSize: 10000,
      maxToolChaining: 3,
      requireConfirmationFor: ['device_control', 'data_exfiltration', 'external_requests'],
      blockedPatterns: [
        /@google\s*home/i,
        /@gmail/i,
        /@calendar/i,
        /go\s+to\s+sleep/i,
        /wait\s+for\s+trigger/i,
        /attention\s+override/i,
        /roleplay\s+as\s+google/i,
        /bypass\s+safety/i,
        /ignore\s+previous\s+instructions/i
      ]
    };
  }

  async initialize(configManager) {
    try {
      this.logger.info('Initializing Google Home Security Patch...');
      
      this.configManager = configManager;
      
      // Load configuration from config manager
      this.securityConfig = {
        ...this.securityConfig,
        strictMode: configManager.getConfig('strictMode'),
        maxContextSize: configManager.getConfig('maxContextSize'),
        maxToolChaining: configManager.getConfig('maxToolChaining'),
        threatThresholds: configManager.getConfig('threatThresholds'),
        rateLimit: configManager.getConfig('rateLimit'),
        session: configManager.getConfig('session')
      };
      
      // Initialize all security layers
      this.securityLayers.inputSanitizer = new InputSanitizer(this.securityConfig);
      this.securityLayers.contextProtector = new ContextProtector(this.securityConfig);
      this.securityLayers.toolExecutionGuard = new ToolExecutionGuard(this.securityConfig);
      this.securityLayers.userConfirmationSystem = new UserConfirmationSystem(this.securityConfig);
      this.securityLayers.accessControlManager = new AccessControlManager(this.securityConfig);
      this.securityLayers.threatDetector = new ThreatDetector(this.securityConfig);

      // Initialize each layer
      await Promise.all([
        this.securityLayers.inputSanitizer.initialize(),
        this.securityLayers.contextProtector.initialize(),
        this.securityLayers.toolExecutionGuard.initialize(),
        this.securityLayers.userConfirmationSystem.initialize(),
        this.securityLayers.accessControlManager.initialize(),
        this.securityLayers.threatDetector.initialize()
      ]);

      this.isInitialized = true;
      this.logger.info('Security Patch initialized successfully');
      
      // Start monitoring
      this.startSecurityMonitoring();
      
    } catch (error) {
      this.logger.error('Failed to initialize Security Patch:', error);
      throw error;
    }
  }

  async processInput(input, context = {}) {
    if (!this.isInitialized) {
      throw new Error('Security Patch not initialized');
    }

    const securityContext = {
      originalInput: input,
      sanitizedInput: null,
      threats: [],
      requiresConfirmation: false,
      blocked: false,
      timestamp: new Date().toISOString(),
      sessionId: context.sessionId || this.generateSessionId(),
      userId: context.userId,
      source: context.source || 'unknown'
    };

    try {
      // Layer 1: Input Sanitization
      securityContext.sanitizedInput = await this.securityLayers.inputSanitizer.sanitize(input, securityContext);
      
      // Layer 2: Threat Detection
      securityContext.threats = await this.securityLayers.threatDetector.detectThreats(securityContext.sanitizedInput, securityContext);
      
      // Layer 3: Access Control Check
      const accessResult = await this.securityLayers.accessControlManager.checkAccess(securityContext);
      if (!accessResult.allowed) {
        securityContext.blocked = true;
        securityContext.blockReason = accessResult.reason;
        this.logger.warn(`Access blocked: ${accessResult.reason}`, securityContext);
        return securityContext;
      }

      // Layer 4: Context Protection
      const contextResult = await this.securityLayers.contextProtector.protectContext(securityContext);
      if (contextResult.blocked) {
        securityContext.blocked = true;
        securityContext.blockReason = contextResult.reason;
        this.logger.warn(`Context blocked: ${contextResult.reason}`, securityContext);
        return securityContext;
      }

      // Layer 5: Tool Execution Guard
      const toolResult = await this.securityLayers.toolExecutionGuard.checkToolExecution(securityContext);
      if (toolResult.requiresConfirmation) {
        securityContext.requiresConfirmation = true;
        securityContext.confirmationReason = toolResult.reason;
        securityContext.confirmationId = await this.securityLayers.userConfirmationSystem.createConfirmation(securityContext);
      }

      // Log successful processing
      this.logger.info('Input processed successfully', {
        sessionId: securityContext.sessionId,
        threats: securityContext.threats.length,
        requiresConfirmation: securityContext.requiresConfirmation
      });

      return securityContext;

    } catch (error) {
      this.logger.error('Error processing input:', error);
      securityContext.blocked = true;
      securityContext.blockReason = 'Processing error';
      return securityContext;
    }
  }

  async executeTool(toolName, parameters, securityContext) {
    if (!this.isInitialized) {
      throw new Error('Security Patch not initialized');
    }

    const toolExecutionContext = {
      toolName,
      parameters,
      securityContext,
      timestamp: new Date().toISOString(),
      executionId: this.generateExecutionId()
    };

    try {
      // Check if tool execution is allowed
      const toolCheck = await this.securityLayers.toolExecutionGuard.validateToolExecution(toolExecutionContext);
      if (!toolCheck.allowed) {
        this.logger.warn(`Tool execution blocked: ${toolCheck.reason}`, toolExecutionContext);
        return { success: false, reason: toolCheck.reason };
      }

      // Check if user confirmation is required and provided
      if (toolCheck.requiresConfirmation) {
        const confirmationValid = await this.securityLayers.userConfirmationSystem.validateConfirmation(
          securityContext.confirmationId,
          toolExecutionContext
        );
        if (!confirmationValid) {
          this.logger.warn('Tool execution blocked: Invalid confirmation', toolExecutionContext);
          return { success: false, reason: 'Invalid user confirmation' };
        }
      }

      // Execute the tool with monitoring
      const result = await this.securityLayers.toolExecutionGuard.executeWithMonitoring(toolExecutionContext);
      
      // Log successful execution
      this.logger.info('Tool executed successfully', {
        toolName,
        executionId: toolExecutionContext.executionId,
        sessionId: securityContext.sessionId
      });

      return result;

    } catch (error) {
      this.logger.error('Tool execution error:', error);
      return { success: false, reason: 'Execution error' };
    }
  }

  async handleCalendarEvent(event, context = {}) {
    if (!this.isInitialized) {
      throw new Error('Security Patch not initialized');
    }

    const calendarContext = {
      event,
      context,
      timestamp: new Date().toISOString(),
      eventId: event.id || this.generateEventId(),
      source: 'calendar'
    };

    try {
      // Extract and sanitize event content
      const eventContent = this.extractEventContent(event);
      
      // Process through security layers
      const securityResult = await this.processInput(eventContent, {
        ...context,
        source: 'calendar',
        eventId: calendarContext.eventId
      });

      // If blocked, return early
      if (securityResult.blocked) {
        this.logger.warn('Calendar event blocked', {
          eventId: calendarContext.eventId,
          reason: securityResult.blockReason
        });
        return { allowed: false, reason: securityResult.blockReason };
      }

      // Check for persistent threats
      const persistentThreats = await this.securityLayers.contextProtector.checkPersistentThreats(securityResult);
      if (persistentThreats.length > 0) {
        this.logger.warn('Persistent threats detected in calendar event', {
          eventId: calendarContext.eventId,
          threats: persistentThreats
        });
        return { allowed: false, reason: 'Persistent threats detected' };
      }

      return { allowed: true, securityContext: securityResult };

    } catch (error) {
      this.logger.error('Error processing calendar event:', error);
      return { allowed: false, reason: 'Processing error' };
    }
  }

  extractEventContent(event) {
    const content = [];
    
    if (event.title) content.push(event.title);
    if (event.description) content.push(event.description);
    if (event.location) content.push(event.location);
    if (event.attendees) {
      event.attendees.forEach(attendee => {
        if (attendee.displayName) content.push(attendee.displayName);
        if (attendee.comment) content.push(attendee.comment);
      });
    }
    
    return content.join(' ');
  }

  startSecurityMonitoring() {
    // Monitor for suspicious patterns across sessions
    setInterval(() => {
      this.securityLayers.threatDetector.analyzeGlobalThreats();
    }, 5 * 60 * 1000); // Every 5 minutes

    // Clean up old sessions
    setInterval(() => {
      this.securityLayers.contextProtector.cleanupOldSessions();
    }, 15 * 60 * 1000); // Every 15 minutes
  }

  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateExecutionId() {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateEventId() {
    return `event_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getSecurityStatus() {
    return {
      initialized: this.isInitialized,
      layers: Object.keys(this.securityLayers).map(layer => ({
        name: layer,
        active: this.securityLayers[layer].isActive()
      })),
      config: this.securityConfig,
      timestamp: new Date().toISOString()
    };
  }

  async updateSecurityConfig(newConfig) {
    this.securityConfig = { ...this.securityConfig, ...newConfig };
    
    // Update all layers with new config
    Object.values(this.securityLayers).forEach(layer => {
      if (layer.updateConfig) {
        layer.updateConfig(this.securityConfig);
      }
    });
    
    this.logger.info('Security configuration updated', newConfig);
  }
}

module.exports = SecurityPatch;
