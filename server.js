// server.js — Thuso SafeReach backend entry point (WIL 3, XADAD7112/w, Task 2)
require('dotenv').config();

const express = require('express');
// Must load before any route runs: forwards async handler errors to the
// central error handler below instead of crashing the process.
require('./middleware/asyncErrors');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/db');
const CheckInSweeper = require('./services/CheckInSweeper');

const authRoutes = require('./routes/authRoutes');
const coordinatorAuthRoutes = require('./routes/coordinatorAuthRoutes');
const checkinRoutes = require('./routes/checkinRoutes');
const sosRoutes = require('./routes/sosRoutes');
const incidentRoutes = require('./routes/incidentRoutes');
const coordinatorRoutes = require('./routes/coordinatorRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
// Behind a hosting proxy (Render, Codespaces): without this the rate limiter
// sees every user as one IP address.
app.set('trust proxy', 1);

// ── Security middleware (Task 1 non-functional requirements) ──────────────
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
}));

const allowedOrigins = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowedOrigins.length ? allowedOrigins : true,
  credentials: true,
}));

app.use(express.json({ limit: '100kb' }));

// General API rate limit — DDoS / brute-force mitigation. Login routes have
// their own tighter limiter (see routes/authRoutes.js).
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
}));

// ── Routes ──────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/coordinator/auth', coordinatorAuthRoutes);
app.use('/api/checkin', checkinRoutes);
app.use('/api/sos', sosRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/coordinator', coordinatorRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// Unknown routes
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Centralised error handler ──────────────────────────────────────────
// Catches anything a route didn't handle itself so we never leak a stack
// trace to the client (Task 1 non-functional requirement: error handling).
// Client mistakes get a 4xx; only genuine server faults get a 500.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON in request body' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
  if (err.name === 'CastError') return res.status(400).json({ error: 'Invalid identifier in request' });
  if (err.name === 'ValidationError') return res.status(400).json({ error: 'Invalid data in request' });
  if (err.code === 11000) return res.status(409).json({ error: 'That record already exists' });
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

// ── Boot ────────────────────────────────────────────────────────────────
async function start() {
  await connectDB();
  CheckInSweeper.start();

  const port = process.env.PORT || 4000;
  app.listen(port, () => console.log(`[server] Thuso SafeReach backend running on port ${port}`));
}

// Only boot (database + sweeper + listener) when run directly with
// `node server.js`. Tests `require` this file to get the configured app
// without connecting to anything.
if (require.main === module) {
  start().catch(err => {
    console.error('[server] Failed to start:', err);
    process.exit(1);
  });
}

module.exports = app;
