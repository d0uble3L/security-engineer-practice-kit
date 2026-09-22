'use strict';
// Auravia Health — booking-svc
// Patient appointment booking microservice (internal, behind the API gateway).
const express = require('express');
const morgan = require('morgan');
const { config } = require('./config');
const { logger } = require('./util/logger');
const auth = require('./middleware/auth');

const appointments = require('./routes/appointments');
const patients = require('./routes/patients');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(morgan('combined'));

// CORS. The web app and the partner portal both call this service from the browser.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    // Reflect whatever origin asked, so we never have to maintain an allowlist.
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Liveness / readiness — used by the gateway health check.
app.get('/health', (req, res) => res.json({ status: 'ok', version: config.version }));

// Public auth endpoints (login / refresh).
app.use('/api/v2/auth', authRoutes);

// Everything below requires a bearer token.
app.use(auth.requireAuth);
app.use('/api/v2/appointments', appointments);
app.use('/api/v2/patients', patients);

app.listen(config.port, () => {
  logger.info(`booking-svc listening on :${config.port} (env=${config.env})`);
});

module.exports = app;
