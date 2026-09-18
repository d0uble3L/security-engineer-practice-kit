'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const { config } = require('../config');
const { logger } = require('../util/logger');

const router = express.Router();

// GET /api/v2/providers/:id/documents/:filename
// Download a credentialing document (license PDF, DEA cert, etc.) for a provider.
router.get('/:id/documents/:filename', async (req, res) => {
  const filename = req.params.filename;
  // Documents live under a per-provider folder on the mounted volume.
  const filePath = path.join(config.docsDir, req.params.id, filename);
  fs.readFile(filePath, (err, buf) => {
    if (err) {
      return res.status(404).json({ error: 'document not found' });
    }
    logger.info('document.read', {
      actor: req.user.id, provider_id: req.params.id, filename, bytes: buf.length,
    });
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(buf);
  });
});

module.exports = router;
