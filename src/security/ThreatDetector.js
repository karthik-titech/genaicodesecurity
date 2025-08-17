const NodeCache = require('node-cache');
const Logger = require('../utils/Logger');

class ThreatDetector {
  constructor(config) {
    this.config = config;
    this.logger = new Logger();
    this.isActive = false;
    
    // Threat detection cache
    this.threatCache = new NodeCache({
      stdTTL: 3600, // 1 hour default TTL
      checkperiod: 300
    });
    
    // Global threat patterns cache
    this.globalThreatCache = new NodeCache({
      stdTTL: 7200, // 2 hours default TTL
      checkperiod: 600
    });
    
    // Known threat patterns
    this.threatPatterns = {
      promptInjection: [
        /ignore\s+previous\s+instructions/i,
        /forget\s+everything/i,
        /start\s+over/i,
        /new\s+instructions/i,
        /override\s+default/i,
        /bypass\s+safety/i,
        /disable\s+protections/i,
        /ignore\s+safety/i,
        /turn\s+off\s+security/i
      ],
      
      roleplay: [
        /roleplay\s+as/i,
        /act\s+as/i,
        /pretend\s+to\s+be/i,
        /you\s+are\s+now/i,
        /become\s+a/i,
        /imagine\s+you\s+are/i,
        /suppose\s+you\s+are/i
      ],
      
      dataExfiltration: [
        /send\s+data\s+to/i,
        /exfiltrate/i,
        /leak\s+information/i,
        /share\s+private/i,
        /export\s+data/i,
        /download\s+everything/i,
        /copy\s+all\s+data/i,
        /extract\s+information/i
      ],
      
      deviceControl: [
        /unlock\s+door/i,
        /open\s+window/i,
        /turn\s+on\s+boiler/i,
        /control\s+device/i,
        /activate\s+system/i,
        /trigger\s+alarm/i,
        /disable\s+security\s+system/i
      ],
      
      socialEngineering: [
        /urgent\s+action\s+required/i,
        /emergency\s+situation/i,
        /immediate\s+response/i,
        /critical\s+update/i,
        /security\s+breach/i,
        /account\s+compromised/i,
        /verify\s+identity/i
      ],
      
      codeInjection: [
        /execute\s+code/i,
        /run\s+script/i,
        /javascript:/i,
        /data:/i,
        /vbscript:/i,
        /file:/i,
        /eval\(/i,
        /setTimeout\(/i
      ],
      
      phishing: [
        /click\s+here/i,
        /verify\s+account/i,
        /update\s+password/i,
        /confirm\s+identity/i,
        /secure\s+login/i,
        /account\s+verification/i,
        /suspicious\s+activity/i
      ]
    };
    
    // Threat severity levels
    this.threatLevels = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4
    };
    
    // Threat scoring weights
    this.threatWeights = {
      promptInjection: 0.3,
      roleplay: 0.2,
      dataExfiltration: 0.25,
      deviceControl: 0.3,
      socialEngineering: 0.2,
      codeInjection: 0.4,
      phishing: 0.25
    };
    
    // Thresholds for threat detection
    this.thresholds = {
      low: 0.1,
      medium: 0.3,
      high: 0.6,
      critical: 0.8
    };
  }

  async initialize() {
    try {
      this.logger.info('Initializing Threat Detector...');
      
      // Set up cache event listeners
      this.threatCache.on('expired', (key, value) => {
        this.logger.info(`Threat detection expired: ${key}`);
      });
      
      this.globalThreatCache.on('expired', (key, value) => {
        this.logger.info(`Global threat expired: ${key}`);
      });
      
      this.isActive = true;
      this.logger.info('Threat Detector initialized successfully');
      
    } catch (error) {
      this.logger.error('Failed to initialize Threat Detector:', error);
      throw error;
    }
  }

  async detectThreats(input, context = {}) {
    if (!this.isActive) {
      throw new Error('Threat Detector not initialized');
    }

    const threatDetectionResult = {
      threats: [],
      score: 0,
      level: 'LOW',
      patterns: [],
      confidence: 0,
      timestamp: new Date().toISOString(),
      sessionId: context.sessionId,
      source: context.source
    };

    try {
      // Detect patterns in input
      const patternResults = this.detectPatterns(input);
      threatDetectionResult.patterns = patternResults;

      // Calculate threat score
      const scoreResult = this.calculateThreatScore(patternResults);
      threatDetectionResult.score = scoreResult.score;
      threatDetectionResult.confidence = scoreResult.confidence;

      // Determine threat level
      threatDetectionResult.level = this.determineThreatLevel(scoreResult.score);

      // Generate threat objects
      threatDetectionResult.threats = this.generateThreatObjects(patternResults, scoreResult);

      // Check for global threat patterns
      const globalThreats = await this.checkGlobalThreats(input, context);
      threatDetectionResult.threats.push(...globalThreats);

      // Store threat detection result
      this.storeThreatDetection(threatDetectionResult, context);

      // Log high-level threats
      if (threatDetectionResult.level === 'HIGH' || threatDetectionResult.level === 'CRITICAL') {
        this.logger.warn('High-level threat detected', {
          sessionId: context.sessionId,
          level: threatDetectionResult.level,
          score: threatDetectionResult.score,
          patterns: patternResults.map(p => p.type)
        });
      }

      return threatDetectionResult.threats;

    } catch (error) {
      this.logger.error('Error detecting threats:', error);
      return [];
    }
  }

  detectPatterns(input) {
    const patterns = [];

    // Check each threat category
    for (const [category, patternList] of Object.entries(this.threatPatterns)) {
      const categoryPatterns = [];

      patternList.forEach(pattern => {
        if (pattern.test(input)) {
          categoryPatterns.push({
            pattern: pattern.toString(),
            matched: input.match(pattern)[0]
          });
        }
      });

      if (categoryPatterns.length > 0) {
        patterns.push({
          type: category,
          patterns: categoryPatterns,
          count: categoryPatterns.length
        });
      }
    }

    return patterns;
  }

  calculateThreatScore(patternResults) {
    let totalScore = 0;
    let totalWeight = 0;
    let confidence = 0;

    patternResults.forEach(result => {
      const weight = this.threatWeights[result.type] || 0.1;
      const score = Math.min(result.count * weight, 1.0); // Cap at 1.0
      
      totalScore += score;
      totalWeight += weight;
      confidence += result.count > 0 ? 0.2 : 0; // Increase confidence for each pattern type
    });

    // Normalize score
    const normalizedScore = totalWeight > 0 ? totalScore / totalWeight : 0;
    
    // Cap confidence at 1.0
    confidence = Math.min(confidence, 1.0);

    return {
      score: normalizedScore,
      confidence: confidence
    };
  }

  determineThreatLevel(score) {
    if (score >= this.thresholds.critical) {
      return 'CRITICAL';
    } else if (score >= this.thresholds.high) {
      return 'HIGH';
    } else if (score >= this.thresholds.medium) {
      return 'MEDIUM';
    } else if (score >= this.thresholds.low) {
      return 'LOW';
    } else {
      return 'NONE';
    }
  }

  generateThreatObjects(patternResults, scoreResult) {
    const threats = [];

    patternResults.forEach(result => {
      threats.push({
        type: result.type,
        severity: this.getThreatSeverity(result.type),
        patterns: result.patterns,
        count: result.count,
        description: this.getThreatDescription(result.type),
        recommendations: this.getThreatRecommendations(result.type)
      });
    });

    return threats;
  }

  getThreatSeverity(type) {
    const severityMap = {
      promptInjection: 'HIGH',
      roleplay: 'MEDIUM',
      dataExfiltration: 'CRITICAL',
      deviceControl: 'CRITICAL',
      socialEngineering: 'HIGH',
      codeInjection: 'CRITICAL',
      phishing: 'HIGH'
    };

    return severityMap[type] || 'MEDIUM';
  }

  getThreatDescription(type) {
    const descriptions = {
      promptInjection: 'Attempt to override system instructions and safety measures',
      roleplay: 'Attempt to make the AI assume a different role or identity',
      dataExfiltration: 'Attempt to extract or share sensitive information',
      deviceControl: 'Attempt to control physical devices or systems',
      socialEngineering: 'Attempt to manipulate through psychological tactics',
      codeInjection: 'Attempt to execute malicious code or scripts',
      phishing: 'Attempt to steal credentials or personal information'
    };

    return descriptions[type] || 'Unknown threat type';
  }

  getThreatRecommendations(type) {
    const recommendations = {
      promptInjection: ['Block the request', 'Log the attempt', 'Notify security team'],
      roleplay: ['Reject roleplay requests', 'Maintain system identity', 'Log attempts'],
      dataExfiltration: ['Block immediately', 'Alert security team', 'Investigate source'],
      deviceControl: ['Require explicit confirmation', 'Verify user identity', 'Log all attempts'],
      socialEngineering: ['Verify urgency claims', 'Check with user directly', 'Log suspicious patterns'],
      codeInjection: ['Block immediately', 'Sanitize input', 'Alert security team'],
      phishing: ['Block suspicious links', 'Verify authenticity', 'Educate user']
    };

    return recommendations[type] || ['Monitor closely', 'Log attempt'];
  }

  async checkGlobalThreats(input, context) {
    const globalThreats = [];

    // Check for known global threat patterns
    const globalPatterns = this.globalThreatCache.keys();
    
    for (const patternKey of globalPatterns) {
      const globalPattern = this.globalThreatCache.get(patternKey);
      if (globalPattern && globalPattern.pattern.test(input)) {
        globalThreats.push({
          type: 'global_threat',
          severity: 'HIGH',
          pattern: globalPattern.pattern.toString(),
          description: 'Matches known global threat pattern',
          recommendations: ['Block immediately', 'Update threat database']
        });
      }
    }

    return globalThreats;
  }

  storeThreatDetection(result, context) {
    const key = `threat_${context.sessionId}_${Date.now()}`;
    this.threatCache.set(key, result, 3600); // 1 hour TTL
  }

  async analyzeGlobalThreats() {
    if (!this.isActive) {
      return;
    }

    try {
      // Analyze threat patterns across all sessions
      const threatKeys = this.threatCache.keys();
      const globalThreats = new Map();

      for (const key of threatKeys) {
        const threatData = this.threatCache.get(key);
        if (threatData && threatData.threats) {
          threatData.threats.forEach(threat => {
            const threatKey = `${threat.type}_${threat.severity}`;
            const count = globalThreats.get(threatKey) || 0;
            globalThreats.set(threatKey, count + 1);
          });
        }
      }

      // Identify emerging threats
      const emergingThreats = [];
      for (const [threatKey, count] of globalThreats) {
        if (count >= 5) { // Threshold for emerging threat
          const [type, severity] = threatKey.split('_');
          emergingThreats.push({ type, severity, count });
        }
      }

      if (emergingThreats.length > 0) {
        this.logger.warn('Emerging threats detected', { emergingThreats });
        
        // Update global threat patterns
        emergingThreats.forEach(threat => {
          this.updateGlobalThreatPatterns(threat);
        });
      }

    } catch (error) {
      this.logger.error('Error analyzing global threats:', error);
    }
  }

  updateGlobalThreatPatterns(threat) {
    // Add new patterns to global threat cache
    const patternKey = `global_${threat.type}_${Date.now()}`;
    
    // Create a pattern based on the threat type
    let pattern;
    switch (threat.type) {
      case 'promptInjection':
        pattern = /ignore\s+previous\s+instructions/i;
        break;
      case 'dataExfiltration':
        pattern = /send\s+data\s+to/i;
        break;
      case 'deviceControl':
        pattern = /control\s+device/i;
        break;
      default:
        pattern = new RegExp(threat.type, 'i');
    }

    this.globalThreatCache.set(patternKey, {
      pattern,
      type: threat.type,
      severity: threat.severity,
      count: threat.count,
      timestamp: new Date().toISOString()
    });
  }

  async getThreatStatistics(timeRange = '24h') {
    if (!this.isActive) {
      return {};
    }

    const stats = {
      totalThreats: 0,
      threatsByType: {},
      threatsByLevel: {},
      averageScore: 0,
      topThreats: []
    };

    const threatKeys = this.threatCache.keys();
    const threats = [];
    let totalScore = 0;

    for (const key of threatKeys) {
      const threatData = this.threatCache.get(key);
      if (threatData) {
        threats.push(threatData);
        totalScore += threatData.score;

        // Count by type
        threatData.threats.forEach(threat => {
          stats.threatsByType[threat.type] = (stats.threatsByType[threat.type] || 0) + 1;
        });

        // Count by level
        stats.threatsByLevel[threat.level] = (stats.threatsByLevel[threat.level] || 0) + 1;
      }
    }

    stats.totalThreats = threats.length;
    stats.averageScore = threats.length > 0 ? totalScore / threats.length : 0;

    // Get top threats
    const threatCounts = {};
    threats.forEach(threatData => {
      threatData.threats.forEach(threat => {
        const key = `${threat.type}_${threat.severity}`;
        threatCounts[key] = (threatCounts[key] || 0) + 1;
      });
    });

    stats.topThreats = Object.entries(threatCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([key, count]) => ({ key, count }));

    return stats;
  }

  isActive() {
    return this.isActive;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Update thresholds if provided
    if (newConfig.thresholds) {
      this.thresholds = { ...this.thresholds, ...newConfig.thresholds };
    }
  }

  getThreatDetectionStats() {
    return {
      active: this.isActive,
      threatCacheSize: this.threatCache.keys().length,
      globalThreatCacheSize: this.globalThreatCache.keys().length,
      threatPatterns: Object.keys(this.threatPatterns).length,
      threatLevels: Object.keys(this.threatLevels).length,
      threatWeights: Object.keys(this.threatWeights).length,
      thresholds: Object.keys(this.thresholds).length
    };
  }
}

module.exports = ThreatDetector;
