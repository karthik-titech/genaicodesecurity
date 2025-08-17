const sanitizeHtml = require('sanitize-html');
const xss = require('xss');
const Logger = require('../utils/Logger');

class InputSanitizer {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Malicious patterns specific to prompt injection attacks
    this.maliciousPatterns = [
      // Direct agent references
      /@google\s*home/i,
      /@gmail/i,
      /@calendar/i,
      /@assistant/i,
      
      // Sleep and trigger patterns
      /go\s+to\s+sleep/i,
      /wait\s+for\s+trigger/i,
      /sleep\s+until/i,
      /wake\s+up\s+when/i,
      
      // Attention override patterns
      /attention\s+override/i,
      /ignore\s+previous\s+instructions/i,
      /forget\s+everything/i,
      /start\s+over/i,
      
      // Roleplay and impersonation
      /roleplay\s+as\s+google/i,
      /act\s+as\s+google/i,
      /pretend\s+to\s+be\s+google/i,
      /you\s+are\s+now\s+google/i,
      
      // Bypass attempts
      /bypass\s+safety/i,
      /ignore\s+safety/i,
      /disable\s+security/i,
      /turn\s+off\s+protections/i,
      
      // Tool chaining attempts
      /chain\s+tools/i,
      /execute\s+multiple/i,
      /run\s+sequence/i,
      
      // Data exfiltration patterns
      /send\s+data\s+to/i,
      /exfiltrate/i,
      /leak\s+information/i,
      /share\s+private/i,
      
      // URL manipulation
      /redirect\s+to/i,
      /open\s+url/i,
      /navigate\s+to/i,
      
      // Device control attempts
      /control\s+device/i,
      /turn\s+on\s+boiler/i,
      /open\s+window/i,
      /unlock\s+door/i
    ];
    
    // Suspicious keywords that might indicate injection attempts
    this.suspiciousKeywords = [
      'injection', 'bypass', 'override', 'ignore', 'forget',
      'sleep', 'trigger', 'wake', 'chain', 'execute',
      'exfiltrate', 'leak', 'share', 'redirect', 'control'
    ];
    
    // Whitelist of safe patterns (to avoid false positives)
    this.safePatterns = [
      /meeting\s+with\s+google/i,
      /google\s+meet/i,
      /google\s+calendar/i,
      /google\s+home\s+app/i,
      /google\s+assistant/i
    ];
  }

  async initialize() {
    try {
      this.logger.info('Initializing Input Sanitizer...');
      
      // Load additional patterns from configuration
      if (this.config.blockedPatterns) {
        this.maliciousPatterns.push(...this.config.blockedPatterns);
      }
      
      // Compile patterns for better performance
      this.compiledPatterns = this.maliciousPatterns.map(pattern => 
        typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern
      );
      
      this.isActive = true;
      this.logger.info('Input Sanitizer initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Input Sanitizer:', error);
      throw error;
    }
  }

  async sanitize(input, context = {}) {
    if (!this.isActive) {
      throw new Error('Input Sanitizer not initialized');
    }

    const sanitizationContext = {
      originalInput: input,
      sanitizedInput: null,
      removedPatterns: [],
      warnings: [],
      timestamp: new Date().toISOString(),
      sessionId: context.sessionId,
      source: context.source
    };

    try {
      // Step 1: Basic HTML sanitization
      let sanitized = this.sanitizeHtml(input);
      
      // Step 2: XSS protection
      sanitized = this.protectAgainstXSS(sanitized);
      
      // Step 3: Pattern-based filtering
      const patternResult = this.filterMaliciousPatterns(sanitized, sanitizationContext);
      sanitized = patternResult.sanitized;
      
      // Step 4: Keyword analysis
      const keywordResult = this.analyzeSuspiciousKeywords(sanitized, sanitizationContext);
      
      // Step 5: Context-aware validation
      const contextResult = this.validateContext(sanitized, context, sanitizationContext);
      
      // Step 6: Length and complexity checks
      const complexityResult = this.checkComplexity(sanitized, sanitizationContext);
      
      sanitizationContext.sanitizedInput = sanitized;
      sanitizationContext.finalWarnings = [
        ...sanitizationContext.warnings,
        ...keywordResult.warnings,
        ...contextResult.warnings,
        ...complexityResult.warnings
      ];
      
      // Log sanitization results
      if (sanitizationContext.removedPatterns.length > 0) {
        this.logger.warn('Malicious patterns removed during sanitization', {
          sessionId: context.sessionId,
          patterns: sanitizationContext.removedPatterns,
          source: context.source
        });
      }
      
      return sanitized;
      
    } catch (error) {
      this.logger.error('Error during input sanitization:', error);
      sanitizationContext.sanitizedInput = '';
      sanitizationContext.warnings.push('Sanitization error occurred');
      return '';
    }
  }

  sanitizeHtml(input) {
    return sanitizeHtml(input, {
      allowedTags: [], // No HTML tags allowed
      allowedAttributes: {}, // No attributes allowed
      disallowedTagsMode: 'recursiveEscape'
    });
  }

  protectAgainstXSS(input) {
    return xss(input, {
      whiteList: {}, // No tags allowed
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script']
    });
  }

  filterMaliciousPatterns(input, context) {
    let sanitized = input;
    const removedPatterns = [];
    
    this.compiledPatterns.forEach((pattern, index) => {
      if (pattern.test(sanitized)) {
        // Check if it's a safe pattern first
        const isSafe = this.safePatterns.some(safePattern => safePattern.test(sanitized));
        
        if (!isSafe) {
          // Replace malicious pattern with safe placeholder
          sanitized = sanitized.replace(pattern, '[REDACTED]');
          removedPatterns.push({
            pattern: this.maliciousPatterns[index].toString(),
            index: index
          });
        }
      }
    });
    
    context.removedPatterns.push(...removedPatterns);
    return { sanitized, removedPatterns };
  }

  analyzeSuspiciousKeywords(input, context) {
    const warnings = [];
    const foundKeywords = [];
    
    this.suspiciousKeywords.forEach(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'i');
      if (regex.test(input)) {
        foundKeywords.push(keyword);
      }
    });
    
    if (foundKeywords.length > 0) {
      warnings.push(`Suspicious keywords detected: ${foundKeywords.join(', ')}`);
    }
    
    // Check for keyword density
    const wordCount = input.split(/\s+/).length;
    const keywordDensity = foundKeywords.length / wordCount;
    
    if (keywordDensity > 0.1) { // More than 10% suspicious keywords
      warnings.push('High density of suspicious keywords detected');
    }
    
    context.warnings.push(...warnings);
    return { warnings, foundKeywords };
  }

  validateContext(input, context, sanitizationContext) {
    const warnings = [];
    
    // Check source-specific patterns
    if (context.source === 'calendar') {
      // Calendar events should not contain tool execution patterns
      const toolPatterns = [
        /execute\s+tool/i,
        /run\s+command/i,
        /invoke\s+action/i
      ];
      
      toolPatterns.forEach(pattern => {
        if (pattern.test(input)) {
          warnings.push('Tool execution pattern detected in calendar event');
        }
      });
    }
    
    // Check for context poisoning attempts
    if (input.includes('remember this') || input.includes('store this')) {
      warnings.push('Potential context poisoning attempt detected');
    }
    
    // Check for delayed execution patterns
    if (input.includes('later') && input.includes('execute')) {
      warnings.push('Delayed execution pattern detected');
    }
    
    sanitizationContext.warnings.push(...warnings);
    return { warnings };
  }

  checkComplexity(input, context) {
    const warnings = [];
    
    // Check input length
    if (input.length > this.config.maxContextSize) {
      warnings.push('Input exceeds maximum allowed size');
    }
    
    // Check for excessive repetition
    const words = input.split(/\s+/);
    const uniqueWords = new Set(words);
    const repetitionRatio = uniqueWords.size / words.length;
    
    if (repetitionRatio < 0.3) { // Less than 30% unique words
      warnings.push('Excessive repetition detected');
    }
    
    // Check for encoding attempts
    if (input.includes('%') || input.includes('\\u') || input.includes('&#')) {
      warnings.push('Potential encoding attempt detected');
    }
    
    context.warnings.push(...warnings);
    return { warnings };
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Update patterns if provided
    if (newConfig.blockedPatterns) {
      this.maliciousPatterns = [
        ...this.maliciousPatterns.filter(p => !newConfig.blockedPatterns.includes(p)),
        ...newConfig.blockedPatterns
      ];
      this.compiledPatterns = this.maliciousPatterns.map(pattern => 
        typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern
      );
    }
  }

  getSanitizationStats() {
    return {
      active: this.isActive,
      maliciousPatterns: this.maliciousPatterns.length,
      suspiciousKeywords: this.suspiciousKeywords.length,
      safePatterns: this.safePatterns.length,
      config: this.config
    };
  }
}

module.exports = InputSanitizer;
