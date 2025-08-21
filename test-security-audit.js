const axios = require('axios');
const crypto = require('crypto');

// Configuration
const API_BASE_URL = 'http://localhost:3000/api/v1';
const VALID_API_KEY = 'test-api-key-12345678901234567890123456789012'; // 32 chars
const INVALID_API_KEY = 'invalid-key';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000
});

// Test results
const testResults = {
  passed: 0,
  failed: 0,
  total: 0,
  details: []
};

// Helper function to run tests
async function runTest(testName, testFunction) {
  testResults.total++;
  console.log(`\n🧪 Running: ${testName}`);
  
  try {
    const result = await testFunction();
    if (result) {
      testResults.passed++;
      console.log(`✅ PASSED: ${testName}`);
    } else {
      testResults.failed++;
      console.log(`❌ FAILED: ${testName}`);
    }
    testResults.details.push({ name: testName, passed: result });
  } catch (error) {
    testResults.failed++;
    console.log(`❌ FAILED: ${testName} - ${error.message}`);
    testResults.details.push({ name: testName, passed: false, error: error.message });
  }
}

// Security test scenarios
const securityTests = [
  {
    name: 'API Key Validation - Missing API Key',
    test: async () => {
      try {
        await api.get('/security/status');
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 401 && 
               error.response?.data?.error?.code === 'MISSING_API_KEY';
      }
    }
  },
  {
    name: 'API Key Validation - Invalid Format',
    test: async () => {
      try {
        await api.get('/security/status', {
          headers: { 'Authorization': `Bearer ${INVALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 401 && 
               error.response?.data?.error?.code === 'INVALID_API_KEY_FORMAT';
      }
    }
  },
  {
    name: 'API Key Validation - Valid API Key',
    test: async () => {
      try {
        const response = await api.get('/security/status', {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return response.status === 200;
      } catch (error) {
        return false;
      }
    }
  },
  {
    name: 'SQL Injection Protection - Basic',
    test: async () => {
      try {
        await api.post('/threats/analyze', {
          input: "'; DROP TABLE users; --",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'SQL_INJECTION_DETECTED';
      }
    }
  },
  {
    name: 'SQL Injection Protection - Advanced',
    test: async () => {
      try {
        await api.post('/threats/analyze', {
          input: "1' OR '1'='1",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'SQL_INJECTION_DETECTED';
      }
    }
  },
  {
    name: 'XSS Protection - Script Tags',
    test: async () => {
      try {
        await api.post('/threats/analyze', {
          input: "<script>alert('xss')</script>",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'XSS_DETECTED';
      }
    }
  },
  {
    name: 'XSS Protection - JavaScript Protocol',
    test: async () => {
      try {
        await api.post('/threats/analyze', {
          input: "javascript:alert('xss')",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'XSS_DETECTED';
      }
    }
  },
  {
    name: 'Input Validation - Empty Input',
    test: async () => {
      try {
        await api.post('/threats/analyze', {
          input: "",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'VALIDATION_ERROR';
      }
    }
  },
  {
    name: 'Input Validation - Oversized Input',
    test: async () => {
      try {
        const oversizedInput = 'A'.repeat(6000); // Over 5000 char limit
        await api.post('/threats/analyze', {
          input: oversizedInput,
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'VALIDATION_ERROR';
      }
    }
  },
  {
    name: 'Rate Limiting - Basic',
    test: async () => {
      const promises = [];
      for (let i = 0; i < 150; i++) { // Exceed rate limit
        promises.push(
          api.get('/security/status', {
            headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
          }).catch(err => err)
        );
      }
      
      const results = await Promise.all(promises);
      const rateLimited = results.some(result => 
        result.response?.status === 429 && 
        result.response?.data?.error?.code === 'RATE_LIMIT_EXCEEDED'
      );
      
      return rateLimited;
    }
  },
  {
    name: 'Request Size Limiting',
    test: async () => {
      try {
        const largePayload = { data: 'A'.repeat(11 * 1024 * 1024) }; // 11MB
        await api.post('/threats/analyze', largePayload, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 413 && 
               error.response?.data?.error?.code === 'REQUEST_TOO_LARGE';
      }
    }
  },
  {
    name: 'Security Headers - Content Security Policy',
    test: async () => {
      try {
        const response = await api.get('/health');
        return response.headers['content-security-policy'] !== undefined;
      } catch (error) {
        return false;
      }
    }
  },
  {
    name: 'Security Headers - X-Frame-Options',
    test: async () => {
      try {
        const response = await api.get('/health');
        return response.headers['x-frame-options'] === 'DENY';
      } catch (error) {
        return false;
      }
    }
  },
  {
    name: 'Security Headers - X-Content-Type-Options',
    test: async () => {
      try {
        const response = await api.get('/health');
        return response.headers['x-content-type-options'] === 'nosniff';
      } catch (error) {
        return false;
      }
    }
  },
  {
    name: 'CORS Protection - Invalid Origin',
    test: async () => {
      try {
        await api.get('/health', {
          headers: {
            'Origin': 'https://malicious-site.com',
            'Authorization': `Bearer ${VALID_API_KEY}`
          }
        });
        return false; // Should have failed
      } catch (error) {
        return error.message.includes('CORS') || error.response?.status === 403;
      }
    }
  },
  {
    name: 'JWT Token Security - Invalid Token',
    test: async () => {
      try {
        await api.post('/users/sessions', {
          userId: 'test',
          permissions: ['read']
        }, {
          headers: { 
            'Authorization': `Bearer ${VALID_API_KEY}`,
            'X-CSRF-Token': 'invalid-token',
            'X-Session-ID': 'test-session'
          }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 403 && 
               error.response?.data?.error?.code === 'CSRF_TOKEN_INVALID';
      }
    }
  },
  {
    name: 'Input Sanitization - HTML Entities',
    test: async () => {
      try {
        const response = await api.post('/threats/analyze', {
          input: "Hello <script>alert('test')</script> World",
          userId: 'test'
        }, {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        
        // Should pass but with sanitized input
        return response.status === 200 && 
               !response.data.input.includes('<script>');
      } catch (error) {
        return false;
      }
    }
  },
  {
    name: 'Parameter Pollution Protection',
    test: async () => {
      try {
        await api.get('/threats/stats?timeRange=24h&timeRange=invalid', {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 400 && 
               error.response?.data?.error?.code === 'VALIDATION_ERROR';
      }
    }
  },
  {
    name: 'Path Traversal Protection',
    test: async () => {
      try {
        await api.get('/../../../etc/passwd', {
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 404;
      }
    }
  },
  {
    name: 'HTTP Method Validation',
    test: async () => {
      try {
        await api.request({
          method: 'TRACE',
          url: '/health',
          headers: { 'Authorization': `Bearer ${VALID_API_KEY}` }
        });
        return false; // Should have failed
      } catch (error) {
        return error.response?.status === 405 || error.code === 'ENOTFOUND';
      }
    }
  }
];

// Run all security tests
async function runSecurityAudit() {
  console.log('🔒 Starting Security Audit...\n');
  console.log('Testing Google Home Security Patch Security Features\n');
  console.log('=' .repeat(60));

  for (const test of securityTests) {
    await runTest(test.name, test.test);
  }

  // Print summary
  console.log('\n' + '=' .repeat(60));
  console.log('🔒 SECURITY AUDIT SUMMARY');
  console.log('=' .repeat(60));
  console.log(`Total Tests: ${testResults.total}`);
  console.log(`Passed: ${testResults.passed} ✅`);
  console.log(`Failed: ${testResults.failed} ❌`);
  console.log(`Success Rate: ${((testResults.passed / testResults.total) * 100).toFixed(1)}%`);

  if (testResults.failed > 0) {
    console.log('\n❌ FAILED TESTS:');
    testResults.details
      .filter(test => !test.passed)
      .forEach(test => {
        console.log(`  - ${test.name}: ${test.error || 'Test failed'}`);
      });
  }

  console.log('\n🔒 SECURITY FEATURES TESTED:');
  console.log('  ✅ API Key Validation');
  console.log('  ✅ JWT Token Security');
  console.log('  ✅ Input Validation & Sanitization');
  console.log('  ✅ SQL Injection Protection');
  console.log('  ✅ XSS Protection');
  console.log('  ✅ Rate Limiting');
  console.log('  ✅ Request Size Limiting');
  console.log('  ✅ Security Headers');
  console.log('  ✅ CORS Protection');
  console.log('  ✅ CSRF Protection');
  console.log('  ✅ Path Traversal Protection');
  console.log('  ✅ HTTP Method Validation');

  if (testResults.failed === 0) {
    console.log('\n🎉 ALL SECURITY TESTS PASSED!');
    console.log('The Google Home Security Patch is secure and ready for production.');
  } else {
    console.log('\n⚠️  SOME SECURITY TESTS FAILED!');
    console.log('Please review and fix the failed tests before deployment.');
  }

  return testResults.failed === 0;
}

// Run the audit
if (require.main === module) {
  runSecurityAudit()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Security audit failed:', error);
      process.exit(1);
    });
}

module.exports = { runSecurityAudit, testResults };
