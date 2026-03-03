/**
 * Cerberus Security Scanner Server
 * Express.js backend that handles vulnerability scanning via n8n webhook
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const routes = require('./routes');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000', 'http://localhost:5173'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, VS Code extensions, etc.)
    if (!origin) return callback(null, true);
    // Allow VS Code extension hosts
    if (origin.startsWith('vscode-webview://') || origin.startsWith('vscode-file://')) {
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    // Log blocked origins for debugging
    console.log(`CORS blocked origin: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Register routes
app.use(routes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred'
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Cerberus server running on http://0.0.0.0:${PORT}`);
  console.log(`📡 n8n webhook: ${process.env.N8N_WEBHOOK_URL || 'https://n8n.shravanpandala.me/webhook/scan'}`);
  console.log(`⏱️  timeout: ${process.env.N8N_TIMEOUT_SECONDS || '20'}s`);
});

module.exports = app;