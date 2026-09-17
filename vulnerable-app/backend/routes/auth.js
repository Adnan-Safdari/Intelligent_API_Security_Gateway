const express = require('express');
const { pool } = require('../db');
const { issueToken } = require('../auth-token');

const router = express.Router();

// POST /api/login
//
// Login intentionally remains a useful brute-force target, but it is not the
// SQL injection demonstration. Keeping the query parameterised makes that
// distinction explicit and leaves the deliberately unsafe behaviour isolated
// to products/search in routes/products.js.
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  console.log(`Login attempt for email: ${email}`);

  try {
    const result = await pool.query(
      `SELECT id, email, role
         FROM users
        WHERE email = $1 AND password = $2
        LIMIT 1`,
      [email, password],
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Login successful!',
      user,
      // A signed JWT: the orders routes and the gateway both verify it.
      token: issueToken(user),
    });
  } catch (error) {
    console.error('Login query failed:', error);
    return res.status(500).json({
      success: false,
      message: 'Login failed',
    });
  }
});

module.exports = router;
