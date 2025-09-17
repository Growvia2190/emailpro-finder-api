// server.js - Complete Email Finder & Verification Backend
const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const net = require('net');
const axios = require('axios');
const cheerio = require('cheerio');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://email-tracker.lovable.app'] 
    : ['http://localhost:3000', 'http://localhost:5173']
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Disposable email domains list
const DISPOSABLE_DOMAINS = new Set([
  '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com',
  'throwaway.email', 'temp-mail.org', '0-mail.com', '33mail.com', 
  'emkei.cz', 'fake-mail.ml', 'getairmail.com', 'getnada.com',
  'mintemail.com', 'mohmal.com', 'mytrashmail.com', 'sharklasers.com',
  'spam4.me', 'tempmail.ninja', 'yopmail.com', '20minutemail.it',
  'emailondeck.com', 'maildrop.cc', 'mailnesia.com', 'tempail.com'
]);

// Common email patterns for domain-based generation
const EMAIL_PATTERNS = [
  'info', 'contact', 'sales', 'support', 'admin', 'hello', 'team',
  'help', 'marketing', 'hr', 'careers', 'business', 'service',
  'office', 'general', 'mail', 'reception', 'customer', 'inquiry'
];

// Cache for DNS lookups to improve performance
const dnsCache = new Map();
const CACHE_TTL = 3600000; // 1 hour

class EmailFinder {
  constructor() {
    this.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
  }

  // Extract emails from HTML content
  extractEmailsFromHTML(html, sourceUrl) {
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = new Set();
    const $ = cheerio.load(html);
    
    // Remove script and style elements
    $('script, style').remove();
    
    // Extract text content
    const text = $.text();
    const matches = text.match(emailRegex) || [];
    
    matches.forEach(email => {
      if (this.isValidEmailFormat(email) && !this.isImageEmail(email)) {
        emails.add(email.toLowerCase());
      }
    });

    // Look for emails in href attributes
    $('a[href^="mailto:"]').each((i, elem) => {
      const href = $(elem).attr('href');
      const email = href.replace('mailto:', '').split('?')[0];
      if (this.isValidEmailFormat(email)) {
        emails.add(email.toLowerCase());
      }
    });

    return Array.from(emails).map(email => ({
      email,
      source: this.determineEmailSource($, email, sourceUrl),
      confidence: this.calculateConfidence(email, sourceUrl),
      type: this.categorizeEmail(email)
    }));
  }

  // Generate pattern-based emails for a domain
  generatePatternEmails(domain) {
    return EMAIL_PATTERNS.map(pattern => ({
      email: `${pattern}@${domain}`,
      source: 'Pattern Generation',
      confidence: this.calculatePatternConfidence(pattern),
      type: this.categorizeEmailByPattern(pattern)
    }));
  }

  // Determine email source from HTML context
  determineEmailSource($, email, sourceUrl) {
    const emailText = email.toLowerCase();
    const pageText = $.text().toLowerCase();
    
    if (pageText.includes('contact') && pageText.indexOf(emailText) > -1) {
      return 'Contact Page';
    } else if ($('footer').text().toLowerCase().includes(emailText)) {
      return 'Footer';
    } else if (pageText.includes('sales') && pageText.indexOf(emailText) > -1) {
      return 'Sales Page';
    } else if (pageText.includes('about') && pageText.indexOf(emailText) > -1) {
      return 'About Page';
    } else if (pageText.includes('support') && pageText.indexOf(emailText) > -1) {
      return 'Support Section';
    }
    
    return 'Web Content';
  }

  // Calculate confidence score for found emails
  calculateConfidence(email, sourceUrl) {
    let confidence = 60; // Base confidence
    
    const [localPart, domain] = email.split('@');
    const sourceDomain = new URL(sourceUrl).hostname.replace('www.', '');
    
    // Higher confidence if email domain matches source domain
    if (domain === sourceDomain) confidence += 30;
    
    // Common business email patterns
    const businessPatterns = ['contact', 'info', 'sales', 'support', 'hello'];
    if (businessPatterns.some(pattern => localPart.includes(pattern))) {
      confidence += 10;
    }
    
    // Lower confidence for personal-looking emails
    if (localPart.length > 15 || localPart.includes('.') && localPart.split('.').length > 2) {
      confidence -= 15;
    }
    
    return Math.min(95, Math.max(25, confidence));
  }

  calculatePatternConfidence(pattern) {
    const highConfidence = ['contact', 'info', 'sales', 'support'];
    const mediumConfidence = ['hello', 'team', 'help', 'marketing'];
    
    if (highConfidence.includes(pattern)) return 85;
    if (mediumConfidence.includes(pattern)) return 70;
    return 55;
  }

  categorizeEmail(email) {
    const localPart = email.split('@')[0].toLowerCase();
    
    if (localPart.includes('sales') || localPart.includes('business')) return 'sales';
    if (localPart.includes('support') || localPart.includes('help')) return 'support';
    if (localPart.includes('info') || localPart.includes('information')) return 'info';
    if (localPart.includes('admin') || localPart.includes('administrator')) return 'admin';
    
    return 'generic';
  }

  categorizeEmailByPattern(pattern) {
    const categories = {
      'sales': 'sales', 'business': 'sales', 'marketing': 'sales',
      'support': 'support', 'help': 'support', 'service': 'support',
      'info': 'info', 'contact': 'info', 'inquiry': 'info',
      'admin': 'admin', 'office': 'admin'
    };
    
    return categories[pattern] || 'generic';
  }

  isValidEmailFormat(email) {
    return validator.isEmail(email) && !email.includes(' ');
  }

  isImageEmail(email) {
    return /\.(jpg|jpeg|png|gif|bmp|svg)$/i.test(email);
  }

  // Fetch and parse website for emails
  async findEmailsFromURL(url, deep = false) {
    try {
      const response = await axios.get(url, {
        headers: { 'User-Agent': this.userAgent },
        timeout: 10000,
        maxRedirects: 5
      });

      let emails = this.extractEmailsFromHTML(response.data, url);
      
      if (deep) {
        // Extract internal links for deeper scanning
        const $ = cheerio.load(response.data);
        const baseUrl = new URL(url);
        const internalLinks = new Set();
        
        $('a[href]').each((i, elem) => {
          const href = $(elem).attr('href');
          if (href && !href.startsWith('http') && !href.startsWith('mailto:')) {
            try {
              const fullUrl = new URL(href, baseUrl).href;
              if (new URL(fullUrl).hostname === baseUrl.hostname) {
                internalLinks.add(fullUrl);
              }
            } catch (e) {
              // Invalid URL, skip
            }
          }
        });

        // Scan up to 5 additional pages
        const pagesToScan = Array.from(internalLinks).slice(0, 5);
        const deepScanPromises = pagesToScan.map(async (pageUrl) => {
          try {
            const pageResponse = await axios.get(pageUrl, {
              headers: { 'User-Agent': this.userAgent },
              timeout: 5000
            });
            return this.extractEmailsFromHTML(pageResponse.data, pageUrl);
          } catch (e) {
            return [];
          }
        });

        const deepResults = await Promise.all(deepScanPromises);
        deepResults.forEach(pageEmails => {
          emails = emails.concat(pageEmails);
        });
      }

      // Remove duplicates
      const uniqueEmails = new Map();
      emails.forEach(emailObj => {
        if (!uniqueEmails.has(emailObj.email)) {
          uniqueEmails.set(emailObj.email, emailObj);
        }
      });

      return Array.from(uniqueEmails.values());
    } catch (error) {
      console.error(`Error fetching ${url}:`, error.message);
      return [];
    }
  }
}

class EmailVerifier {
  constructor() {
    this.timeout = 5000;
  }

  // Comprehensive email verification
  async verifyEmail(email) {
    const startTime = Date.now();
    
    try {
      const [localPart, domain] = email.split('@');
      
      // Step 1: Syntax validation
      if (!validator.isEmail(email)) {
        return this.createVerificationResult(email, 'invalid', 'Invalid email format', startTime);
      }

      // Step 2: Check for disposable email
      if (this.isDisposableEmail(domain)) {
        return this.createVerificationResult(email, 'risky', 'Disposable email service', startTime);
      }

      // Step 3: Domain validation
      const domainExists = await this.checkDomain(domain);
      if (!domainExists) {
        return this.createVerificationResult(email, 'invalid', 'Domain does not exist', startTime);
      }

      // Step 4: MX record check
      const mxRecords = await this.checkMXRecord(domain);
      if (!mxRecords || mxRecords.length === 0) {
        return this.createVerificationResult(email, 'invalid', 'No mail server found', startTime);
      }

      // Step 5: SMTP verification
      const smtpResult = await this.verifySMTP(email, mxRecords[0].exchange);
      
      let status = 'unknown';
      let reason = 'Unable to verify';

      if (smtpResult.valid) {
        status = 'valid';
        reason = 'Valid mailbox';
      } else if (smtpResult.invalid) {
        status = 'invalid';
        reason = smtpResult.reason || 'Mailbox not found';
      } else {
        // Check if it's a role-based email
        if (this.isRoleBasedEmail(localPart)) {
          status = 'risky';
          reason = 'Role-based email';
        } else {
          status = 'unknown';
          reason = 'Verification inconclusive';
        }
      }

      return this.createVerificationResult(email, status, reason, startTime, {
        mxRecord: true,
        smtpCheck: smtpResult.checked,
        disposable: false,
        riskScore: this.calculateRiskScore(email, status)
      });

    } catch (error) {
      console.error(`Error verifying ${email}:`, error.message);
      return this.createVerificationResult(email, 'unknown', 'Verification failed', startTime);
    }
  }

  createVerificationResult(email, status, reason, startTime, additional = {}) {
    return {
      email,
      status,
      reason,
      deliverable: status === 'valid' ? 'Yes' : status === 'invalid' ? 'No' : 'Maybe',
      responseTime: Date.now() - startTime,
      mxRecord: additional.mxRecord || false,
      smtpCheck: additional.smtpCheck || false,
      disposable: additional.disposable || this.isDisposableEmail(email.split('@')[1]),
      riskScore: additional.riskScore || this.calculateRiskScore(email, status)
    };
  }

  async checkDomain(domain) {
    const cacheKey = `domain_${domain}`;
    
    if (dnsCache.has(cacheKey)) {
      const cached = dnsCache.get(cacheKey);
      if (Date.now() - cached.timestamp < CACHE_TTL) {
        return cached.value;
      }
    }

    try {
      await dns.lookup(domain);
      dnsCache.set(cacheKey, { value: true, timestamp: Date.now() });
      return true;
    } catch (error) {
      dnsCache.set(cacheKey, { value: false, timestamp: Date.now() });
      return false;
    }
  }

  async checkMXRecord(domain) {
    const cacheKey = `mx_${domain}`;
    
    if (dnsCache.has(cacheKey)) {
      const cached = dnsCache.get(cacheKey);
      if (Date.now() - cached.timestamp < CACHE_TTL) {
        return cached.value;
      }
    }

    try {
      const mxRecords = await dns.resolveMx(domain);
      const sortedRecords = mxRecords.sort((a, b) => a.priority - b.priority);
      dnsCache.set(cacheKey, { value: sortedRecords, timestamp: Date.now() });
      return sortedRecords;
    } catch (error) {
      dnsCache.set(cacheKey, { value: null, timestamp: Date.now() });
      return null;
    }
  }

  async verifySMTP(email, mxHost) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let response = '';
      let step = 0;
      
      const cleanup = () => {
        socket.destroy();
      };

      const timeout = setTimeout(() => {
        cleanup();
        resolve({ valid: false, invalid: false, checked: false, reason: 'Timeout' });
      }, this.timeout);

      socket.connect(25, mxHost, () => {
        // Connection established, wait for greeting
      });

      socket.on('data', (data) => {
        response += data.toString();
        
        if (response.includes('\n')) {
          const lines = response.split('\n');
          const lastLine = lines[lines.length - 2] || lines[lines.length - 1];
          const code = parseInt(lastLine.substring(0, 3));

          switch (step) {
            case 0: // Initial greeting
              if (code === 220) {
                socket.write(`HELO ${mxHost}\r\n`);
                step = 1;
              } else {
                cleanup();
                clearTimeout(timeout);
                resolve({ valid: false, invalid: true, checked: true, reason: 'Server rejected connection' });
              }
              break;
              
            case 1: // HELO response
              if (code === 250) {
                socket.write(`MAIL FROM:<test@test.com>\r\n`);
                step = 2;
              } else {
                cleanup();
                clearTimeout(timeout);
                resolve({ valid: false, invalid: false, checked: true, reason: 'HELO failed' });
              }
              break;
              
            case 2: // MAIL FROM response
              if (code === 250) {
                socket.write(`RCPT TO:<${email}>\r\n`);
                step = 3;
              } else {
                cleanup();
                clearTimeout(timeout);
                resolve({ valid: false, invalid: false, checked: true, reason: 'MAIL FROM failed' });
              }
              break;
              
            case 3: // RCPT TO response
              cleanup();
              clearTimeout(timeout);
              
              if (code === 250) {
                resolve({ valid: true, invalid: false, checked: true, reason: 'Accepted' });
              } else if (code === 550 || code === 551 || code === 553) {
                resolve({ valid: false, invalid: true, checked: true, reason: 'Mailbox not found' });
              } else if (code === 552) {
                resolve({ valid: false, invalid: true, checked: true, reason: 'Mailbox full' });
              } else {
                resolve({ valid: false, invalid: false, checked: true, reason: `Server response: ${code}` });
              }
              break;
          }
          
          response = '';
        }
      });

      socket.on('error', (error) => {
        cleanup();
        clearTimeout(timeout);
        resolve({ valid: false, invalid: false, checked: false, reason: error.message });
      });

      socket.on('close', () => {
        cleanup();
        clearTimeout(timeout);
        if (step < 3) {
          resolve({ valid: false, invalid: false, checked: false, reason: 'Connection closed prematurely' });
        }
      });
    });
  }

  isDisposableEmail(domain) {
    return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
  }

  isRoleBasedEmail(localPart) {
    const roleBasedPrefixes = [
      'admin', 'administrator', 'postmaster', 'hostmaster', 'webmaster',
      'www', 'abuse', 'noreply', 'no-reply', 'support', 'info', 'marketing',
      'sales', 'help', 'mail', 'contact', 'team', 'staff', 'office'
    ];
    
    const lowerLocal = localPart.toLowerCase();
    return roleBasedPrefixes.some(prefix => lowerLocal.includes(prefix));
  }

  calculateRiskScore(email, status) {
    let risk = 0;
    const [localPart, domain] = email.split('@');
    
    // Base risk by status
    if (status === 'invalid') risk += 90;
    else if (status === 'risky') risk += 60;
    else if (status === 'unknown') risk += 40;
    else if (status === 'valid') risk += 10;
    
    // Additional risk factors
    if (this.isRoleBasedEmail(localPart)) risk += 20;
    if (this.isDisposableEmail(domain)) risk += 30;
    if (localPart.length < 3) risk += 15;
    if (localPart.includes('test') || localPart.includes('temp')) risk += 25;
    
    return Math.min(100, risk);
  }
}

// Initialize services
const emailFinder = new EmailFinder();
const emailVerifier = new EmailVerifier();

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'EmailPro Finder API',
    version: '1.0.0',
    status: 'active',
    endpoints: ['/api/find-emails', '/api/verify-emails', '/api/health']
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Email finding endpoint
app.post('/api/find-emails', async (req, res) => {
  try {
    const { url, domain, deep = false } = req.body;
    
    if (!url && !domain) {
      return res.status(400).json({ error: 'URL or domain is required' });
    }

    let emails = [];
    
    // Find emails from URL
    if (url) {
      try {
        const foundEmails = await emailFinder.findEmailsFromURL(url, deep);
        emails = emails.concat(foundEmails);
      } catch (error) {
        console.error('URL scanning error:', error);
      }
    }
    
    // Generate pattern emails for domain
    if (domain) {
      const patternEmails = emailFinder.generatePatternEmails(domain);
      emails = emails.concat(patternEmails);
    }
    
    // Remove duplicates and sort by confidence
    const uniqueEmails = new Map();
    emails.forEach(emailObj => {
      const key = emailObj.email.toLowerCase();
      if (!uniqueEmails.has(key) || uniqueEmails.get(key).confidence < emailObj.confidence) {
        uniqueEmails.set(key, emailObj);
      }
    });

    const sortedEmails = Array.from(uniqueEmails.values())
      .sort((a, b) => b.confidence - a.confidence);

    res.json({
      success: true,
      emails: sortedEmails,
      count: sortedEmails.length,
      source: url || domain
    });

  } catch (error) {
    console.error('Email finding error:', error);
    res.status(500).json({
      error: 'Failed to find emails',
      message: error.message
    });
  }
});

// Email verification endpoint
app.post('/api/verify-emails', async (req, res) => {
  try {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails)) {
      return res.status(400).json({ error: 'Emails array is required' });
    }

    if (emails.length > 1000) {
      return res.status(400).json({ error: 'Maximum 1000 emails per request' });
    }

    const results = [];
    const batchSize = 10; // Process in batches to avoid overwhelming servers
    
    for (let i = 0; i < emails.length; i += batchSize) {
      const batch = emails.slice(i, i + batchSize);
      const batchPromises = batch.map(email => 
        emailVerifier.verifyEmail(email.trim().toLowerCase())
      );
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Small delay between batches
      if (i + batchSize < emails.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    // Calculate statistics
    const stats = {
      total: results.length,
      valid: results.filter(r => r.status === 'valid').length,
      invalid: results.filter(r => r.status === 'invalid').length,
      risky: results.filter(r => r.status === 'risky').length,
      unknown: results.filter(r => r.status === 'unknown').length,
      deliverable: results.filter(r => r.deliverable === 'Yes').length
    };

    res.json({
      success: true,
      results,
      statistics: stats,
      successRate: Math.round((stats.valid / stats.total) * 100)
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      error: 'Failed to verify emails',
      message: error.message
    });
  }
});

// Single email verification endpoint
app.post('/api/verify-single', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const result = await emailVerifier.verifyEmail(email.trim().toLowerCase());
    
    res.json({
      success: true,
      result
    });

  } catch (error) {
    console.error('Single email verification error:', error);
    res.status(500).json({
      error: 'Failed to verify email',
      message: error.message
    });
  }
});

// Domain analysis endpoint
app.post('/api/analyze-domain', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '');
    
    // Check domain validity
    const domainExists = await emailVerifier.checkDomain(cleanDomain);
    const mxRecords = await emailVerifier.checkMXRecord(cleanDomain);
    
    // Generate pattern emails
    const patternEmails = emailFinder.generatePatternEmails(cleanDomain);
    
    // Quick verify a few common patterns
    const commonPatterns = ['info', 'contact', 'sales', 'support'];
    const quickVerifications = await Promise.all(
      commonPatterns.map(async pattern => {
        const email = `${pattern}@${cleanDomain}`;
        return await emailVerifier.verifyEmail(email);
      })
    );

    res.json({
      success: true,
      domain: cleanDomain,
      analysis: {
        domainExists,
        hasMxRecords: mxRecords && mxRecords.length > 0,
        mxRecords: mxRecords || [],
        isDisposable: emailVerifier.isDisposableEmail(cleanDomain)
      },
      patternEmails,
      quickVerifications
    });

  } catch (error) {
    console.error('Domain analysis error:', error);
    res.status(500).json({
      error: 'Failed to analyze domain',
      message: error.message
    });
  }
});

// Bulk domain analysis
app.post('/api/analyze-domains', async (req, res) => {
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({ error: 'Domains array is required' });
    }

    const results = await Promise.all(
      domains.map(async domain => {
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '');
        
        try {
          const domainExists = await emailVerifier.checkDomain(cleanDomain);
          const mxRecords = await emailVerifier.checkMXRecord(cleanDomain);
          
          return {
            domain: cleanDomain,
            exists: domainExists,
            hasMxRecords: mxRecords && mxRecords.length > 0,
            isDisposable: emailVerifier.isDisposableEmail(cleanDomain),
            mxCount: mxRecords ? mxRecords.length : 0
          };
        } catch (error) {
          return {
            domain: cleanDomain,
            exists: false,
            hasMxRecords: false,
            isDisposable: false,
            error: error.message
          };
        }
      })
    );

    res.json({
      success: true,
      results,
      summary: {
        total: results.length,
        valid: results.filter(r => r.exists && r.hasMxRecords).length,
        invalid: results.filter(r => !r.exists).length,
        disposable: results.filter(r => r.isDisposable).length
      }
    });

  } catch (error) {
    console.error('Bulk domain analysis error:', error);
    res.status(500).json({
      error: 'Failed to analyze domains',
      message: error.message
    });
  }
});

// Export verification results
app.post('/api/export', async (req, res) => {
  try {
    const { results, format = 'csv' } = req.body;
    
    if (!results || !Array.isArray(results)) {
      return res.status(400).json({ error: 'Results array is required' });
    }

    if (format === 'csv') {
      const headers = Object.keys(results[0]);
      const csvContent = [
        headers.join(','),
        ...results.map(row => 
          headers.map(header => {
            const value = row[header];
            return typeof value === 'string' && value.includes(',') 
              ? `"${value}"` 
              : value;
          }).join(',')
        )
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=email_results.csv');
      res.send(csvContent);
    } else if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename=email_results.json');
      res.json(results);
    } else {
      res.status(400).json({ error: 'Unsupported format' });
    }

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      error: 'Failed to export results',
      message: error.message
    });
  }
});

// Statistics endpoint
app.get('/api/stats', (req, res) => {
  const stats = {
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cacheSize: dnsCache.size,
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  };
  
  res.json(stats);
});

// Clear cache endpoint (admin)
app.post('/api/clear-cache', (req, res) => {
  dnsCache.clear();
  res.json({ message: 'Cache cleared successfully' });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 EmailPro Finder API running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔍 Email finding and verification service ready!`);
});
