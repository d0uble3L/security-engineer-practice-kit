'use strict';
const { Pool } = require('pg');
const { config } = require('./config');

const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  max: 10,
  idleTimeoutMillis: 30000,
});

// Thin wrapper so routes don't import pg directly.
async function query(text, params) {
  return pool.query(text, params);
}

// Convenience for the few places that build SQL as a string.
async function raw(text) {
  return pool.query(text);
}

module.exports = { pool, query, raw };
