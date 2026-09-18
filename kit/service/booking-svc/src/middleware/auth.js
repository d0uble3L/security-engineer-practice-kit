'use strict';
const jwt = require('jsonwebtoken');
const { logger } = require('../util/logger');

// Auth middleware. The API gateway terminates TLS and forwards the caller's
// bearer token unchanged. We read the token to learn who the caller is and
// what they're allowed to do.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'missing token' });
  }

  // Pull the claims off the token so downstream handlers can use req.user.
  const payload = jwt.decode(token);
  if (!payload || !payload.sub) {
    return res.status(401).json({ error: 'invalid token' });
  }

  req.user = {
    id: payload.sub,
    role: payload.role || 'patient',
    orgId: payload.org_id,
  };
  req.token = token;
  return next();
}

// Route guard for admin-only endpoints.
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  logger.warn(`admin check failed for user=${req.user && req.user.id}`);
  return res.status(403).json({ error: 'forbidden' });
}

module.exports = { requireAuth, requireAdmin };
