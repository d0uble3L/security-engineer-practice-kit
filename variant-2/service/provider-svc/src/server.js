'use strict';
// Auravia Health — provider-svc
// Provider directory, credentialing, and availability service (internal, behind
// the API gateway). Serves the clinician-facing portal and the admin console.
const express = require('express');
const morgan = require('morgan');
const { config } = require('./config');
const { logger } = require('./util/logger');
const auth = require('./middleware/auth');

const providers = require('./routes/providers');
const documents = require('./routes/documents');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(morgan('combined'));

app.get('/health', (req, res) => res.json({ status: 'ok', version: config.version }));

app.use('/api/v2/auth', authRoutes);

// Everything below requires a bearer token.
app.use(auth.requireAuth);
app.use('/api/v2/providers', providers);
app.use('/api/v2/providers', documents);

app.listen(config.port, () => {
  logger.info(`provider-svc listening on :${config.port} (env=${config.env})`);
});

module.exports = app;
