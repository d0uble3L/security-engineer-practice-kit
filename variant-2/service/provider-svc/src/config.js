'use strict';
// Central config for provider-svc. Real secrets come from the environment /
// mounted secret store in every deployed environment.

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '8081', 10),
  version: '1.9.0',

  db: {
    host: process.env.PGHOST || 'db.internal.auravia.local',
    port: parseInt(process.env.PGPORT || '5432', 10),
    user: process.env.PGUSER || 'provider_svc',
    password: process.env.PGPASSWORD,          // required; no fallback
    database: process.env.PGDATABASE || 'auravia_providers',
  },

  // Signing secret for session JWTs, shared with the gateway. Required at boot.
  jwtSecret: process.env.JWT_SECRET,

  // Public verification key for tokens minted by the partner SSO (RS256).
  // This is a PUBLIC key and is intentionally committed so the service can
  // verify partner tokens offline. It is not a secret.
  partnerSsoPublicKey:
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-EXAMPLE-PUBLIC-KEY-NOT-A-SECRET-0000',

  // Where provider credentialing documents are stored on the mounted volume.
  docsDir: process.env.DOCS_DIR || '/var/auravia/provider-docs',

  // Base timeout for outbound availability syncs.
  syncTimeoutMs: parseInt(process.env.SYNC_TIMEOUT_MS || '4000', 10),
};

module.exports = { config };
