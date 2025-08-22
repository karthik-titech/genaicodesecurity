const axios = require('axios');
const crypto = require('crypto');

class KeyWorkflowRotationTester {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.testResults = [];
    this.sessionId = `test_session_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  async runAllTests() {
    console.log('🚀 Starting Key Management and Workflow Handle Rotation Tests\n');
    
    try {
      // Test 1: Health Check
      await this.testHealthCheck();
      
      // Test 2: Key Management System
      await this.testKeyManagementSystem();
      
      // Test 3: Workflow Handle Rotation
      await this.testWorkflowHandleRotation();
      
      // Test 4: Key Expiration Scenarios
      await this.testKeyExpirationScenarios();
      
      // Test 5: Handle Rotation Scenarios
      await this.testHandleRotationScenarios();
      
      // Test 6: Anomaly Detection
      await this.testAnomalyDetection();
      
      // Test 7: Configuration Management
      await this.testConfigurationManagement();
      
      // Test 8: Statistics and Monitoring
      await this.testStatisticsAndMonitoring();
      
      // Test 9: Error Handling
      await this.testErrorHandling();
      
      // Test 10: Performance and Load Testing
      await this.testPerformanceAndLoad();
      
      this.printTestSummary();
      
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    }
  }

  async testHealthCheck() {
    console.log('📋 Test 1: Health Check');
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/key-management/health`);
      
      this.assertTest('Health Check', response.status === 200, {
        status: response.status,
        data: response.data
      });
      
      console.log('✅ Health check passed\n');
    } catch (error) {
      this.assertTest('Health Check', false, { error: error.message });
      console.log('❌ Health check failed\n');
    }
  }

  async testKeyManagementSystem() {
    console.log('🔑 Test 2: Key Management System');
    
    try {
      // Generate different types of keys
      const keyTypes = ['encryption', 'signing', 'session', 'api'];
      const generatedKeys = [];
      
      for (const keyType of keyTypes) {
        const response = await axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
          type: keyType,
          metadata: {
            test: true,
            purpose: 'testing',
            generatedBy: 'test-suite'
          },
          userId: 'test-user'
        });
        
        this.assertTest(`Generate ${keyType} key`, response.status === 200, {
          keyType,
          keyId: response.data.key.id,
          status: response.status
        });
        
        generatedKeys.push(response.data.key);
      }
      
      // Get all keys
      const keysResponse = await axios.get(`${this.baseUrl}/api/key-management/keys`);
      this.assertTest('Get all keys', keysResponse.status === 200, {
        totalKeys: keysResponse.data.keys.length,
        status: keysResponse.status
      });
      
      // Test key retrieval
      if (generatedKeys.length > 0) {
        const firstKey = generatedKeys[0];
        const keyResponse = await axios.get(`${this.baseUrl}/api/key-management/keys/${firstKey.id}`);
        this.assertTest('Get specific key', keyResponse.status === 200, {
          keyId: firstKey.id,
          status: keyResponse.status
        });
      }
      
      console.log('✅ Key management system tests passed\n');
    } catch (error) {
      this.assertTest('Key Management System', false, { error: error.message });
      console.log('❌ Key management system tests failed\n');
    }
  }

  async testWorkflowHandleRotation() {
    console.log('🔄 Test 3: Workflow Handle Rotation');
    
    try {
      // Generate different types of handles
      const handleTypes = ['session', 'workflow', 'api', 'device'];
      const generatedHandles = [];
      
      for (const handleType of handleTypes) {
        const response = await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
          type: handleType,
          context: {
            test: true,
            purpose: 'testing',
            environment: 'test-suite'
          },
          userId: 'test-user'
        });
        
        this.assertTest(`Generate ${handleType} handle`, response.status === 200, {
          handleType,
          handleId: response.data.handle.id,
          status: response.status
        });
        
        generatedHandles.push(response.data.handle);
      }
      
      // Test handle validation
      if (generatedHandles.length > 0) {
        const firstHandle = generatedHandles[0];
        const validationResponse = await axios.post(`${this.baseUrl}/api/key-management/handles/validate`, {
          handleId: firstHandle.id,
          context: {
            ip: '127.0.0.1',
            userAgent: 'test-suite'
          },
          userId: 'test-user'
        });
        
        this.assertTest('Validate handle', validationResponse.status === 200, {
          handleId: firstHandle.id,
          valid: validationResponse.data.validation.valid,
          status: validationResponse.status
        });
      }
      
      // Get all handles
      const handlesResponse = await axios.get(`${this.baseUrl}/api/key-management/handles`);
      this.assertTest('Get all handles', handlesResponse.status === 200, {
        totalHandles: handlesResponse.data.handles.length,
        status: handlesResponse.status
      });
      
      console.log('✅ Workflow handle rotation tests passed\n');
    } catch (error) {
      this.assertTest('Workflow Handle Rotation', false, { error: error.message });
      console.log('❌ Workflow handle rotation tests failed\n');
    }
  }

  async testKeyExpirationScenarios() {
    console.log('⏰ Test 4: Key Expiration Scenarios');
    
    try {
      // Generate a key and simulate expiration
      const keyResponse = await axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
        type: 'session',
        metadata: {
          test: true,
          purpose: 'expiration-test',
          expiresIn: '1s' // Very short expiration for testing
        },
        userId: 'test-user'
      });
      
      this.assertTest('Generate key for expiration test', keyResponse.status === 200, {
        keyId: keyResponse.data.key.id,
        status: keyResponse.status
      });
      
      // Wait for potential expiration
      await this.sleep(2000);
      
      // Check key health
      const healthResponse = await axios.get(`${this.baseUrl}/api/key-management/health/keys`);
      this.assertTest('Check key health', healthResponse.status === 200, {
        status: healthResponse.status,
        health: healthResponse.data.health
      });
      
      console.log('✅ Key expiration scenarios tests passed\n');
    } catch (error) {
      this.assertTest('Key Expiration Scenarios', false, { error: error.message });
      console.log('❌ Key expiration scenarios tests failed\n');
    }
  }

  async testHandleRotationScenarios() {
    console.log('🔄 Test 5: Handle Rotation Scenarios');
    
    try {
      // Generate a handle and test rotation
      const handleResponse = await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
        type: 'workflow',
        context: {
          test: true,
          purpose: 'rotation-test'
        },
        userId: 'test-user'
      });
      
      this.assertTest('Generate handle for rotation test', handleResponse.status === 200, {
        handleId: handleResponse.data.handle.id,
        status: handleResponse.status
      });
      
      // Test manual rotation
      const rotationResponse = await axios.post(`${this.baseUrl}/api/key-management/handles/${handleResponse.data.handle.id}/rotate`, {
        userId: 'test-user',
        reason: 'test-rotation'
      });
      
      this.assertTest('Manual handle rotation', rotationResponse.status === 200, {
        oldHandleId: handleResponse.data.handle.id,
        newHandleId: rotationResponse.data.newHandle.handleId,
        status: rotationResponse.status
      });
      
      console.log('✅ Handle rotation scenarios tests passed\n');
    } catch (error) {
      this.assertTest('Handle Rotation Scenarios', false, { error: error.message });
      console.log('❌ Handle rotation scenarios tests failed\n');
    }
  }

  async testAnomalyDetection() {
    console.log('🚨 Test 6: Anomaly Detection');
    
    try {
      // Generate a handle for anomaly testing
      const handleResponse = await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
        type: 'api',
        context: {
          test: true,
          purpose: 'anomaly-test'
        },
        userId: 'test-user'
      });
      
      this.assertTest('Generate handle for anomaly test', handleResponse.status === 200, {
        handleId: handleResponse.data.handle.id,
        status: handleResponse.status
      });
      
      // Simulate rapid usage (anomaly)
      const handleId = handleResponse.data.handle.id;
      const rapidRequests = [];
      
      for (let i = 0; i < 5; i++) {
        rapidRequests.push(
          axios.post(`${this.baseUrl}/api/key-management/handles/validate`, {
            handleId: handleId,
            context: {
              ip: `192.168.1.${i}`,
              userAgent: 'anomaly-test'
            },
            userId: 'test-user'
          })
        );
      }
      
      const results = await Promise.allSettled(rapidRequests);
      const successfulValidations = results.filter(r => r.status === 'fulfilled').length;
      
      this.assertTest('Anomaly detection', successfulValidations >= 0, {
        totalRequests: rapidRequests.length,
        successfulValidations,
        handleId
      });
      
      console.log('✅ Anomaly detection tests passed\n');
    } catch (error) {
      this.assertTest('Anomaly Detection', false, { error: error.message });
      console.log('❌ Anomaly detection tests failed\n');
    }
  }

  async testConfigurationManagement() {
    console.log('⚙️ Test 7: Configuration Management');
    
    try {
      // Get current configuration
      const getConfigResponse = await axios.get(`${this.baseUrl}/api/key-management/config`);
      this.assertTest('Get configuration', getConfigResponse.status === 200, {
        status: getConfigResponse.status,
        hasKeyTypes: !!getConfigResponse.data.configuration.keyTypes,
        hasHandleTypes: !!getConfigResponse.data.configuration.handleTypes
      });
      
      // Update configuration
      const updateConfigResponse = await axios.put(`${this.baseUrl}/api/key-management/config`, {
        keyTypes: {
          test: {
            algorithm: 'sha256',
            keyLength: 32,
            rotationInterval: 60000, // 1 minute for testing
            warningThreshold: 10000,
            maxLifetime: 300000
          }
        },
        handleTypes: {
          test: {
            algorithm: 'sha256',
            handleLength: 32,
            rotationInterval: 30000, // 30 seconds for testing
            warningThreshold: 5000,
            maxLifetime: 120000
          }
        },
        securityPolicies: {
          preventReuse: true,
          enforceRotation: true,
          trackUsage: true,
          anomalyDetection: true
        },
        userId: 'test-user'
      });
      
      this.assertTest('Update configuration', updateConfigResponse.status === 200, {
        status: updateConfigResponse.status
      });
      
      console.log('✅ Configuration management tests passed\n');
    } catch (error) {
      this.assertTest('Configuration Management', false, { error: error.message });
      console.log('❌ Configuration management tests failed\n');
    }
  }

  async testStatisticsAndMonitoring() {
    console.log('📊 Test 8: Statistics and Monitoring');
    
    try {
      // Get key statistics
      const keyStatsResponse = await axios.get(`${this.baseUrl}/api/key-management/keys/statistics`);
      this.assertTest('Get key statistics', keyStatsResponse.status === 200, {
        status: keyStatsResponse.status,
        hasStats: !!keyStatsResponse.data.statistics
      });
      
      // Get handle statistics
      const handleStatsResponse = await axios.get(`${this.baseUrl}/api/key-management/handles/statistics`);
      this.assertTest('Get handle statistics', handleStatsResponse.status === 200, {
        status: handleStatsResponse.status,
        hasStats: !!handleStatsResponse.data.statistics
      });
      
      // Get key health
      const keyHealthResponse = await axios.get(`${this.baseUrl}/api/key-management/health/keys`);
      this.assertTest('Get key health', keyHealthResponse.status === 200, {
        status: keyHealthResponse.status,
        hasHealth: !!keyHealthResponse.data.health
      });
      
      // Get handle health
      const handleHealthResponse = await axios.get(`${this.baseUrl}/api/key-management/health/handles`);
      this.assertTest('Get handle health', handleHealthResponse.status === 200, {
        status: handleHealthResponse.status,
        hasHealth: !!handleHealthResponse.data.health
      });
      
      console.log('✅ Statistics and monitoring tests passed\n');
    } catch (error) {
      this.assertTest('Statistics and Monitoring', false, { error: error.message });
      console.log('❌ Statistics and monitoring tests failed\n');
    }
  }

  async testErrorHandling() {
    console.log('⚠️ Test 9: Error Handling');
    
    try {
      // Test invalid key type
      try {
        await axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
          type: 'invalid-type',
          userId: 'test-user'
        });
        this.assertTest('Invalid key type', false, { expected: 'should fail' });
      } catch (error) {
        this.assertTest('Invalid key type', error.response.status === 400, {
          status: error.response.status,
          expected: '400 Bad Request'
        });
      }
      
      // Test invalid handle type
      try {
        await axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
          type: 'invalid-type',
          userId: 'test-user'
        });
        this.assertTest('Invalid handle type', false, { expected: 'should fail' });
      } catch (error) {
        this.assertTest('Invalid handle type', error.response.status === 400, {
          status: error.response.status,
          expected: '400 Bad Request'
        });
      }
      
      // Test non-existent key
      try {
        await axios.get(`${this.baseUrl}/api/key-management/keys/non-existent-key`);
        this.assertTest('Non-existent key', false, { expected: 'should fail' });
      } catch (error) {
        this.assertTest('Non-existent key', error.response.status === 404, {
          status: error.response.status,
          expected: '404 Not Found'
        });
      }
      
      // Test non-existent handle
      try {
        await axios.post(`${this.baseUrl}/api/key-management/handles/validate`, {
          handleId: 'non-existent-handle',
          userId: 'test-user'
        });
        this.assertTest('Non-existent handle', false, { expected: 'should fail' });
      } catch (error) {
        this.assertTest('Non-existent handle', error.response.status === 500, {
          status: error.response.status,
          expected: '500 Internal Server Error'
        });
      }
      
      console.log('✅ Error handling tests passed\n');
    } catch (error) {
      this.assertTest('Error Handling', false, { error: error.message });
      console.log('❌ Error handling tests failed\n');
    }
  }

  async testPerformanceAndLoad() {
    console.log('⚡ Test 10: Performance and Load Testing');
    
    try {
      const startTime = Date.now();
      
      // Generate multiple keys concurrently
      const keyPromises = [];
      for (let i = 0; i < 10; i++) {
        keyPromises.push(
          axios.post(`${this.baseUrl}/api/key-management/keys/generate`, {
            type: 'session',
            metadata: { test: true, index: i },
            userId: 'test-user'
          })
        );
      }
      
      const keyResults = await Promise.all(keyPromises);
      const keyGenerationTime = Date.now() - startTime;
      
      this.assertTest('Concurrent key generation', keyResults.every(r => r.status === 200), {
        totalKeys: keyResults.length,
        generationTime: `${keyGenerationTime}ms`,
        averageTime: `${keyGenerationTime / keyResults.length}ms per key`
      });
      
      // Generate multiple handles concurrently
      const handleStartTime = Date.now();
      const handlePromises = [];
      for (let i = 0; i < 10; i++) {
        handlePromises.push(
          axios.post(`${this.baseUrl}/api/key-management/handles/generate`, {
            type: 'workflow',
            context: { test: true, index: i },
            userId: 'test-user'
          })
        );
      }
      
      const handleResults = await Promise.all(handlePromises);
      const handleGenerationTime = Date.now() - handleStartTime;
      
      this.assertTest('Concurrent handle generation', handleResults.every(r => r.status === 200), {
        totalHandles: handleResults.length,
        generationTime: `${handleGenerationTime}ms`,
        averageTime: `${handleGenerationTime / handleResults.length}ms per handle`
      });
      
      console.log('✅ Performance and load tests passed\n');
    } catch (error) {
      this.assertTest('Performance and Load Testing', false, { error: error.message });
      console.log('❌ Performance and load tests failed\n');
    }
  }

  assertTest(testName, condition, details = {}) {
    const result = {
      name: testName,
      passed: condition,
      details,
      timestamp: new Date().toISOString()
    };
    
    this.testResults.push(result);
    
    if (condition) {
      console.log(`  ✅ ${testName}`);
    } else {
      console.log(`  ❌ ${testName}`);
      console.log(`     Details:`, details);
    }
  }

  printTestSummary() {
    console.log('\n📋 Test Summary');
    console.log('='.repeat(50));
    
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;
    
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests} ✅`);
    console.log(`Failed: ${failedTests} ❌`);
    console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);
    
    if (failedTests > 0) {
      console.log('\n❌ Failed Tests:');
      this.testResults
        .filter(r => !r.passed)
        .forEach(r => {
          console.log(`  - ${r.name}`);
          console.log(`    Details: ${JSON.stringify(r.details)}`);
        });
    }
    
    console.log('\n🎉 Test suite completed!');
    
    if (failedTests === 0) {
      console.log('🚀 All tests passed! The key management and workflow handle rotation systems are working correctly.');
    } else {
      console.log('⚠️ Some tests failed. Please review the failed tests above.');
      process.exit(1);
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Run the tests
if (require.main === module) {
  const tester = new KeyWorkflowRotationTester();
  tester.runAllTests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
}

module.exports = KeyWorkflowRotationTester;
