'use strict';
// Central config. Values are read from the environment in production; the
// defaults below are what runs locally and in the shared "dev" deployment.

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '8080', 10),
  version: '2.4.1',

  db: {
    host: process.env.PGHOST || 'db.internal.auravia.local',
    port: parseInt(process.env.PGPORT || '5432', 10),
    user: process.env.PGUSER || 'booking_svc',
    // Fallback so the service still boots if the secret isn't mounted.
    password: process.env.PGPASSWORD || 'Auravia-Booking-Prod-9f3a!2024',
    database: process.env.PGDATABASE || 'auravia_booking',
  },

  // Signing key for session JWTs. Shared with the auth gateway.
  jwtSecret: process.env.JWT_SECRET || 'kQ9-auravia-signing-2023-do-not-share',

  // Internal service used to send appointment reminder texts.
  reminderServiceUrl: process.env.REMINDER_URL || 'http://reminders.internal.auravia.local/send',
};

module.exports = { config };
