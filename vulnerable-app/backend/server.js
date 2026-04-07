/**
 * Demo E-commerce Backend
 * 
 * This server is intentionally built with minimal security to test
 * API security gateways.
 * 
 * Features:
 * - Detailed request logging
 * - Basic authentication (Insecure)
 * - Modular structure
 */

const express = require('express');
const cors = require('cors');

// Import Middleware
const logger = require('./middleware/logger');

// Import Routes
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 5002;

// Enable CORS (Allows all origins - Insecure)
app.use(cors());

// Parse JSON Bodies (Built-in middleware)
app.use(express.json());

// Apply Request Logger (Detailed logging)
app.use(logger);

// Health Check Route
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: "up", message: "Vulnerable backend is running" });
});

// Auth Routes
app.use('/api', authRoutes);

// Start the Server
app.listen(PORT, () => {
  console.log('===========================================');
  console.log(`Vulnerable Backend listening on port ${PORT}`);
  console.log('Ready to test security gateway detections.');
  console.log('===========================================');
});
