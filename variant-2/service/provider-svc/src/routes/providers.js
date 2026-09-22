'use strict';
const express = require('express');
const axios = require('axios');
const semver = require('semver');
const db = require('../db');
const { config } = require('../config');
const { requireAdmin } = require('../middleware/auth');
const { logger } = require('../util/logger');

const router = express.Router();

// Minimum availability-feed format we accept. Compared against a version string
// that comes from OUR config / the feed's own metadata, never raw user input.
const MIN_FEED_VERSION = '2.0.0';

// GET /api/v2/providers/:id  — provider profile
router.get('/:id', async (req, res) => {
  try {
    const r = await db.query(
      'SELECT id, full_name, npi, specialty, role, credential_status, email, phone ' +
        'FROM providers WHERE id = $1',
      [req.params.id]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'not found' });
    return res.json(r.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'lookup failed' });
  }
});

// PATCH /api/v2/providers/:id  — update a provider profile.
// Providers may edit their own contact details.
router.patch('/:id', async (req, res) => {
  try {
    const cur = await db.query('SELECT * FROM providers WHERE id = $1', [req.params.id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not found' });

    // Merge the submitted fields onto the existing record and save.
    const updated = { ...cur.rows[0], ...req.body };
    await db.query(
      'UPDATE providers SET full_name=$1, specialty=$2, email=$3, phone=$4, ' +
        'role=$5, credential_status=$6 WHERE id=$7',
      [updated.full_name, updated.specialty, updated.email, updated.phone,
       updated.role, updated.credential_status, req.params.id]
    );
    logger.info('provider.updated', { actor: req.user.id, provider_id: req.params.id });
    return res.json({ ok: true, id: req.params.id });
  } catch (err) {
    return res.status(500).json({ error: 'update failed' });
  }
});

// POST /api/v2/providers/:id/verify  — mark a provider as credentialed.
// Credentialing is an administrative action performed by the med-staff office.
router.post('/:id/verify', async (req, res) => {
  try {
    await db.query(
      "UPDATE providers SET credential_status='verified', verified_by=$1, verified_at=now() WHERE id=$2",
      [req.user.id, req.params.id]
    );
    logger.info('provider.verify', { actor: req.user.id, provider_id: req.params.id });
    return res.json({ ok: true, provider_id: req.params.id, status: 'verified' });
  } catch (err) {
    return res.status(500).json({ error: 'verify failed' });
  }
});

// POST /api/v2/providers/:id/availability/sync
// Import a provider's availability from an external calendar feed they configure.
router.post('/:id/availability/sync', async (req, res) => {
  const sourceUrl = (req.body && req.body.source_url) || '';
  if (!sourceUrl) return res.status(400).json({ error: 'source_url required' });
  try {
    // Fetch the feed the provider pointed us at and import its slots.
    const resp = await axios.get(sourceUrl, { timeout: config.syncTimeoutMs });
    const feedVersion = (resp.data && resp.data.format_version) || '2.0.0';
    if (semver.lt(feedVersion, MIN_FEED_VERSION)) {
      return res.status(422).json({ error: 'unsupported feed version', feedVersion });
    }
    const slots = (resp.data && resp.data.slots) || [];
    logger.info('availability.sync', {
      actor: req.user.id, provider_id: req.params.id,
      source_url: sourceUrl, fetch_status: resp.status, slot_count: slots.length,
    });
    return res.json({ ok: true, imported: slots.length });
  } catch (err) {
    // Include upstream detail so providers can fix a bad feed URL themselves.
    return res.status(502).json({ error: 'sync failed', detail: String(err.response ? err.response.data : err.message) });
  }
});

module.exports = router;
