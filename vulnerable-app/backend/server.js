const express = require('express');
const cors = require('cors');

// Import Middleware
const logger = require('./middleware/logger');
const { initDb } = require('./db');

// Import Routes
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 5002;

// Enable CORS
app.use(cors());

// Parse JSON
app.use(express.json());

// Logger
app.use(logger);

// Health Check
app.get('/api/health', (req, res) => {
res.status(200).json({ status: "up", message: "Vulnerable backend is running" });
});

// Routes
app.use('/api', authRoutes);

// 🔥 Start server FIRST
app.listen(PORT, async () => {
console.log('===========================================');
console.log(`Vulnerable Backend listening on port ${PORT}`);
console.log('Initializing database in background...');
console.log('===========================================');

// 🔥 Init DB without crashing server
try {
await initDb();
console.log('Database initialized successfully');
} catch (error) {
console.error('Database init failed (non-blocking):', error.message);
}
});

