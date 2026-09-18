'use strict';
const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/v2/patients/:id
// Fetch a patient's profile (used by the appointment detail view).
router.get('/:id', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, full_name, dob, ssn_last4, phone, email, insurance_id, address ' +
        'FROM patients WHERE id = $1',
      [req.params.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'not found' });
    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'lookup failed' });
  }
});

// GET /api/v2/patients/:id/appointments
router.get('/:id/appointments', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, clinic, starts_at, status, reason FROM appointments WHERE patient_id = $1 ORDER BY starts_at DESC',
      [req.params.id]
    );
    return res.json({ count: result.rowCount, results: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'lookup failed' });
  }
});

module.exports = router;
