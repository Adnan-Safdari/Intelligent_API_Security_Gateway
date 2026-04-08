const express = require('express');
const router = express.Router();
const users = require('../data/users');
const { pool } = require('../db');

let AUTH_MODE = (process.env.AUTH_MODE || 'memory').toLowerCase();

router.post('/set-mode', (req, res) => {
  const { mode } = req.body;

  if (!['memory', 'db_vulnerable', 'db_secure'].includes(mode)) {
    return res.status(400).json({ error: 'Invalid mode' });
  }

  AUTH_MODE = mode;

  console.log("🔁 AUTH MODE CHANGED TO:", AUTH_MODE);

  return res.json({ success: true, mode: AUTH_MODE });
});

// POST /api/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  console.log(`Login attempt for email: ${email}`);

  if (AUTH_MODE === 'memory') {
    const looksLikeSqlInjection = (value) =>
      typeof value === 'string' && (
        value.toUpperCase().includes('OR') ||
        value.includes('--') ||
        value.includes("'")
      );

    // 🚨 SIMULATED SQL INJECTION VULNERABILITY
    if (
      looksLikeSqlInjection(email) ||
      looksLikeSqlInjection(password)
    ) {
      console.log('⚠️ SQL Injection simulated → BYPASS');

      return res.status(200).json({
        user: {
          _id: '1',
          name: 'Admin',
          email: 'admin@example.com',
          isAdmin: true
        },
        token: 'fake-jwt-token'
      });
    }

    // Normal logic
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.password === password) {
      return res.status(200).json({
        success: true,
        message: 'Login successful!',
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      });
    } else {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
  }

  try {
    if (AUTH_MODE === 'db_vulnerable') {
  const query = `
    SELECT id, email, role
    FROM users
    WHERE email = '${email}' AND password = '${password}'
    LIMIT 1
  `;

  const result = await pool.query(query);
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid email or password'
    });
  }

  return res.status(200).json({
    success: true,
    message: 'Login successful!',
    user
  });
}
if (AUTH_MODE === 'db_secure') {
  const query = `
    SELECT id, email, role
    FROM users
    WHERE email = $1 AND password = $2
    LIMIT 1
  `;

  const result = await pool.query(query, [email, password]);
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid email or password'
    });
  }

  return res.status(200).json({
    success: true,
    message: 'Login successful!',
    user
  });
}
  } catch (error) {
    console.error('Login query failed:', error);
    return res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
  return res.status(400).json({
  success: false,
  message: 'Invalid AUTH_MODE configuration'
});
});

module.exports = router; 