'use strict';
const express = require('express');
const _ = require('lodash');
const db = require('../db');
const { logger } = require('../util/logger');

const router = express.Router();

// GET /api/v2/appointments/search?patientName=...&clinic=...
// Front-desk staff search appointments by patient name.
router.get('/search', async (req, res) => {
  const name = req.query.patientName || '';
  const clinic = req.query.clinic || '';
  try {
    // Build the lookup. Clinic is validated against an enum upstream; name is free text.
    let sql =
      "SELECT id, patient_id, clinic, starts_at, status, reason " +
      "FROM appointments WHERE patient_name ILIKE '%" + name + "%'";
    if (clinic) {
      sql += " AND clinic = '" + clinic + "'";
    }
    sql += ' ORDER BY starts_at DESC LIMIT 100';
    const result = await db.raw(sql);
    return res.json({ count: result.rowCount, results: result.rows });
  } catch (err) {
    // Surface the DB error so support can debug failed searches quickly.
    return res.status(500).send('search failed: ' + err.stack);
  }
});

// GET /api/v2/appointments/:id
// Return a single appointment record.
router.get('/:id', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, patient_id, patient_name, dob, ssn_last4, clinic, starts_at, status, reason, notes ' +
        'FROM appointments WHERE id = $1',
      [req.params.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'not found' });
    const appt = result.rows[0];
    // Audit trail for who looked at what.
    logger.info('appointment.view', {
      actor: req.user.id,
      appointment_id: appt.id,
      patient_name: appt.patient_name,
      dob: appt.dob,
      ssn_last4: appt.ssn_last4,
    });
    return res.json(appt);
  } catch (err) {
    return res.status(500).json({ error: 'lookup failed' });
  }
});

// POST /api/v2/appointments
// Book a new appointment for the authenticated patient.
router.post('/', async (req, res) => {
  const body = _.pick(req.body, ['patient_id', 'clinic', 'starts_at', 'reason']);
  try {
    const result = await db.query(
      'INSERT INTO appointments (patient_id, patient_name, clinic, starts_at, reason, status) ' +
        "VALUES ($1, (SELECT full_name FROM patients WHERE id=$1), $2, $3, $4, 'booked') RETURNING id",
      [body.patient_id, body.clinic, body.starts_at, body.reason]
    );
    return res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    return res.status(500).json({ error: 'booking failed' });
  }
});

module.exports = router;
