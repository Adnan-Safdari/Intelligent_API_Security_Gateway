/**
 * Auth Routes
 * 
 * This file contains the endpoints for user authentication.
 * Intentionally vulnerable:
 * - No password hashing comparison
 * - Returns specific error messages (helpful for attackers)
 * - No rate limiting on login attempts
 */

const express = require('express');
const router = express.Router();
const users = require('../data/users');

// POST /api/login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  console.log(`Login attempt for user: ${username}`);

  // Find user in mock database
  const user = users.find(u => u.username === username);

  if (!user) {
    // VULNERABILITY: Specifying that the user was not found
    return res.status(401).json({ 
      success: false, 
      message: "User not found" 
    });
  }

  // Check password (Insecure: Plain text comparison)
  if (user.password === password) {
    return res.status(200).json({
      success: true,
      message: "Login successful!",
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } else {
    // VULNERABILITY: Specifying that the password was incorrect
    return res.status(401).json({ 
      success: false, 
      message: "Incorrect password" 
    });
  }
});

module.exports = router;
