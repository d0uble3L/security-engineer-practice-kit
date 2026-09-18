'use strict';
// Minimal structured logger. Writes JSON lines to stdout; the platform's
// log shipper forwards these to the SIEM index `booking-svc-app`.
function emit(level, msg, extra) {
  const line = Object.assign(
    { ts: new Date().toISOString(), level, msg },
    extra || {}
  );
  process.stdout.write(JSON.stringify(line) + '\n');
}

const logger = {
  info: (m, e) => emit('info', m, e),
  warn: (m, e) => emit('warn', m, e),
  error: (m, e) => emit('error', m, e),
};

module.exports = { logger };
