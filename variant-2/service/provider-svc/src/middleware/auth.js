'use strict';
const jwt = require('jsonwebtoken');
const { config } = require('../config');
const { logger } = require('../util/logger');

// Auth middleware. The gateway forwards the caller's bearer token unchanged.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });

  try {
    // Verify the session token. (Signature IS checked here.)
    const payload = jwt.verify(token, config.jwtSecret);
    req.user = {
      id: payload.sub,
      role: payload.role || 'provider',
      providerId: payload.provider_id,
      orgId: payload.org_id,
    };
    req.token = token;
    return next();
  } catch (err) {
    logger.info('auth.reject', { reason: 'verify_failed' });
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Route guard for admin-only endpoints. Wire this AFTER requireAuth.
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  logger.warn('admin check failed', { user: req.user && req.user.id });
  return res.status(403).json({ error: 'forbidden' });
}

module.exports = { requireAuth, requireAdmin };
