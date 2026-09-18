'use strict';
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { config } = require('../config');
const { logger } = require('../util/logger');

const router = express.Router();

// POST /api/v2/auth/login
// Exchange username + password for a session JWT.
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    const result = await db.query(
      'SELECT id, password_hash, role, org_id FROM users WHERE username = $1',
      [username]
    );
    if (result.rowCount === 0) {
      logger.info('auth.login', { username, outcome: 'fail', reason: 'no_user' });
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      logger.info('auth.login', { username, outcome: 'fail', reason: 'bad_password' });
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const token = jwt.sign(
      { sub: user.id, role: user.role, org_id: user.org_id },
      config.jwtSecret,
      { expiresIn: '12h' }
    );
    logger.info('auth.login', { username, outcome: 'success', user_id: user.id });
    return res.json({ token });
  } catch (err) {
    return res.status(500).json({ error: 'login failed' });
  }
});

module.exports = router;
