'use strict';
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { config } = require('../config');
const { logger } = require('../util/logger');

const router = express.Router();

// POST /api/v2/auth/login — exchange username + password for a session JWT.
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    const result = await db.query(
      'SELECT id, password_hash, role, provider_id, org_id FROM users WHERE username = $1',
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
      { sub: user.id, role: user.role, provider_id: user.provider_id, org_id: user.org_id },
      config.jwtSecret,
      { algorithm: 'HS256', expiresIn: '12h' }
    );
    logger.info('auth.login', { username, outcome: 'success', user_id: user.id });
    return res.json({ token });
  } catch (err) {
    return res.status(500).json({ error: 'login failed' });
  }
});

// POST /api/v2/auth/register — self-service provider signup (pending credentialing).
router.post('/register', async (req, res) => {
  const { username, password, full_name, npi } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const p = await db.query(
      "INSERT INTO providers (full_name, npi, role, credential_status) VALUES ($1,$2,'provider','pending') RETURNING id",
      [full_name || username, npi || null]
    );
    const providerId = p.rows[0].id;
    await db.query(
      "INSERT INTO users (username, password_hash, role, provider_id) VALUES ($1,$2,'provider',$3)",
      [username, hash, providerId]
    );
    logger.info('auth.register', { username, provider_id: providerId });
    return res.status(201).json({ ok: true, provider_id: providerId });
  } catch (err) {
    return res.status(500).json({ error: 'registration failed' });
  }
});

module.exports = router;
