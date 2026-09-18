'use strict';
// Minimal JSON logger. In production these lines ship to the SIEM.
// app events  -> index: provider-svc-app
// (auth gateway emits its own audit stream -> index: auravia-gw-auth)
function emit(level, msg, fields) {
  const line = Object.assign(
    { ts: new Date().toISOString(), level, event: msg },
    fields || {}
  );
  process.stdout.write(JSON.stringify(line) + '\n');
}
const logger = {
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};
module.exports = { logger };
