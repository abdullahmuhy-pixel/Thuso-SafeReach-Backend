// server.js — Thuso SafeReach backend entry point (WIL 3, XADAD7112/w, Task 2)
require('dotenv').config();

const express = require('express');
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

// ── Centralised error handler ──────────────────────────────────────────
// Catches anything a route didn't handle itself so we never leak a stack
// trace to the client (Task 1 non-functional requirement: error handling).
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Boot ────────────────────────────────────────────────────────────────
async function start() {
  await connectDB();
  CheckInSweeper.start();

  const port = process.env.PORT || 4000;
  app.listen(port, () => console.log(`[server] Thuso SafeReach backend running on port ${port}`));
}

start().catch(err => {
  console.error('[server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;
