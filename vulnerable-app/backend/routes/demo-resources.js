const express = require('express');
const fs = require('fs/promises');
const path = require('path');

const router = express.Router();

// These are planted, non-sensitive resources for forced-browsing and traversal
// demonstrations. They intentionally contain no application configuration,
// credentials, or host data.
router.get('/backup-demo', (_req, res) => {
  res.status(200).json({
    demo: true,
    resource: 'backup-demo',
    message: 'Harmless planted backup marker for the enumeration demonstration.',
  });
});

router.get('/config-demo', (_req, res) => {
  res.status(200).json({
    demo: true,
    resource: 'config-demo',
    message: 'Harmless planted configuration marker; this is not application configuration.',
  });
});

router.get('/.env-demo', (_req, res) => {
  res.status(200).json({
    demo: true,
    resource: '.env-demo',
    message: 'Harmless planted environment-file marker; no environment values are exposed.',
  });
});

const demoFilesRoot = path.resolve(__dirname, '..', 'demo-files');
const demoFilesPrefix = `${demoFilesRoot}${path.sep}`;

// GET /api/demo-files?file=public/public.txt
//
// This deliberately permits a relative path such as
// "public/../fake-secret.txt". The resolved path is nevertheless required to
// remain under demo-files, so traversal can never reach the container or host
// filesystem. Every readable file is a static, fake demo fixture.
router.get('/api/demo-files', async (req, res) => {
  const file = typeof req.query.file === 'string' ? req.query.file : 'public/public.txt';
  const resolved = path.resolve(demoFilesRoot, file);

  if (!resolved.startsWith(demoFilesPrefix)) {
    return res.status(404).json({
      demo: true,
      message: 'Requested demo file is outside the isolated demo directory.',
    });
  }

  try {
    const content = await fs.readFile(resolved, 'utf8');
    return res.status(200).json({ demo: true, file, content });
  } catch {
    return res.status(404).json({ demo: true, message: 'Demo file not found.' });
  }
});

module.exports = router;
