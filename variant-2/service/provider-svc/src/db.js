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

async function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query };
