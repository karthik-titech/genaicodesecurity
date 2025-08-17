const axios = require('axios');

class SecurityPatchAPI {
  constructor(config = {}) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'http://localhost:3000/api/v1';
    this.timeout = config.timeout || 30000;
    this.retries = config.retries || 3;
    
    // Create axios instance
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'GoogleHomeSecurityPatch-SDK/1.0.0'
      }
    });

    // Add request interceptor for retries
    this.client.interceptors.response.use(
      response => response,
      async error => {
        if (error.response?.status >= 500 && this.retries > 0) {
          this.retries--;
          return this.client.request(error.config);
        }
        throw error;
      }
    );

    // Initialize service modules
    this.security = new SecurityService(this.client);
    this.googleHome = new GoogleHomeService(this.client);
    this.calendar = new CalendarService(this.client);
    this.threats = new ThreatService(this.client);
    this.users = new UserService(this.client);
    this.config = new ConfigService(this.client);
    this.webhooks = new WebhookService(this.client);
    this.test = new TestService(this.client);
  }

  // Health check
  async health() {
    try {
      const response = await this.client.get('/health');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get API version
  async version() {
    try {
      const response = await this.client.get('/version');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Error handler
  handleError(error) {
    if (error.response) {
      return new Error(`API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class SecurityService {
  constructor(client) {
    this.client = client;
  }

  // Get security status
  async getStatus() {
    try {
      const response = await this.client.get('/security/status');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get security statistics
  async getStats() {
    try {
      const response = await this.client.get('/security/stats');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Update security configuration
  async updateConfig(config) {
    try {
      const response = await this.client.post('/security/config', config);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get configuration
  async getConfig() {
    try {
      const response = await this.client.get('/security/config');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Update secrets
  async updateSecret(key, value) {
    try {
      const response = await this.client.post('/security/secrets', { key, value });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get secrets summary
  async getSecrets() {
    try {
      const response = await this.client.get('/security/secrets');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Security API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class GoogleHomeService {
  constructor(client) {
    this.client = client;
  }

  // Process Google Home input
  async process(input, userId, context = {}) {
    try {
      const response = await this.client.post('/google-home/process', {
        input,
        userId,
        context
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Execute Google Home command
  async execute(command, deviceId, parameters = {}, userId, confirmationId = null) {
    try {
      const payload = {
        command,
        deviceId,
        parameters,
        userId
      };
      
      if (confirmationId) {
        payload.confirmationId = confirmationId;
      }

      const response = await this.client.post('/google-home/execute', payload);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get device status
  async getDeviceStatus(deviceId) {
    try {
      const response = await this.client.get(`/google-home/devices/${deviceId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // List devices
  async listDevices() {
    try {
      const response = await this.client.get('/google-home/devices');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get device permissions
  async getDevicePermissions(deviceId) {
    try {
      const response = await this.client.get(`/google-home/devices/${deviceId}/permissions`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Update device permissions
  async updateDevicePermissions(deviceId, permissions) {
    try {
      const response = await this.client.put(`/google-home/devices/${deviceId}/permissions`, {
        permissions
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Google Home API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class CalendarService {
  constructor(client) {
    this.client = client;
  }

  // Process calendar event
  async processEvent(event, userId) {
    try {
      const response = await this.client.post('/calendar/process-event', {
        event,
        userId
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Validate calendar event
  async validateEvent(event) {
    try {
      const response = await this.client.post('/calendar/validate', { event });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get calendar security status
  async getSecurityStatus() {
    try {
      const response = await this.client.get('/calendar/security-status');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get calendar threat statistics
  async getThreatStats() {
    try {
      const response = await this.client.get('/calendar/threat-stats');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Test calendar security
  async testSecurity() {
    try {
      const response = await this.client.post('/calendar/test');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Calendar API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class ThreatService {
  constructor(client) {
    this.client = client;
  }

  // Analyze input for threats
  async analyze(input, context = {}) {
    try {
      const response = await this.client.post('/threats/analyze', {
        input,
        context
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get threat statistics
  async getStats(timeRange = '24h') {
    try {
      const response = await this.client.get(`/threats/stats?timeRange=${timeRange}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get threat history
  async getHistory(limit = 50, offset = 0) {
    try {
      const response = await this.client.get(`/threats/history?limit=${limit}&offset=${offset}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Threat API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class UserService {
  constructor(client) {
    this.client = client;
  }

  // Create user session
  async createSession(userId, permissions, sessionDuration = 3600) {
    try {
      const response = await this.client.post('/users/sessions', {
        userId,
        permissions,
        sessionDuration
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get user permissions
  async getPermissions(userId) {
    try {
      const response = await this.client.get(`/users/${userId}/permissions`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Update user permissions
  async updatePermissions(userId, permissions) {
    try {
      const response = await this.client.put(`/users/${userId}/permissions`, {
        permissions
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Invalidate session
  async invalidateSession(sessionId) {
    try {
      const response = await this.client.delete(`/users/sessions/${sessionId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`User API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class ConfigService {
  constructor(client) {
    this.client = client;
  }

  // Get configuration
  async get() {
    try {
      const response = await this.client.get('/config');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Update configuration
  async update(config) {
    try {
      const response = await this.client.put('/config', config);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Config API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class WebhookService {
  constructor(client) {
    this.client = client;
  }

  // Configure webhook
  async configure(url, events, secret) {
    try {
      const response = await this.client.post('/webhooks', {
        url,
        events,
        secret
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // List webhooks
  async list() {
    try {
      const response = await this.client.get('/webhooks');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Delete webhook
  async delete(webhookId) {
    try {
      const response = await this.client.delete(`/webhooks/${webhookId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Webhook API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

class TestService {
  constructor(client) {
    this.client = client;
  }

  // Test security scenarios
  async security(scenarios) {
    try {
      const response = await this.client.post('/test/security', { scenarios });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Test connectivity
  async connectivity() {
    try {
      const response = await this.client.get('/test/connectivity');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  handleError(error) {
    if (error.response) {
      return new Error(`Test API Error: ${error.response.status} - ${error.response.data?.error?.message || error.message}`);
    }
    return error;
  }
}

module.exports = SecurityPatchAPI;
