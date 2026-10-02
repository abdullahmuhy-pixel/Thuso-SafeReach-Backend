#!/bin/sh
# apply-tests.sh — adds the automated test suite and wires it into CircleCI.
# Run from the repo root:  sh apply-tests.sh
set -e
[ -f server.js ] && [ -d routes ] || { echo "Run this from the repo root (the folder containing server.js)."; exit 1; }
[ -f services/TwoFactorService.js ] && grep -q "reset-2fa" routes/adminRoutes.js || { echo "Install the 2FA update first (sh apply-2fa.sh), then run this."; exit 1; }
mkdir -p tests/helpers services .circleci
cat > services/AuthService.js << '__SAFEREACH_EOF__'
// services/AuthService.js
// Singleton pattern (Task 1, Section 4.3). All JWT issuing and verification
// goes through this one instance rather than being reimplemented in each
// route file. With medical data in the system, we wanted exactly one place
// that decides "is this user allowed to see this" — not three slightly
// different versions of that check scattered around the codebase.
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// 12 in production. Tests set BCRYPT_ROUNDS=4 so hashing doesn't slow them down.
const SALT_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 12;

class AuthService {
  constructor() {
    if (AuthService._instance) {
      return AuthService._instance;
    }
    this.jwtSecret = process.env.JWT_SECRET;
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    AuthService._instance = this;
  }

  async hashPassword(plainPassword) {
    return bcrypt.hash(plainPassword, SALT_ROUNDS);
  }

  async verifyPassword(plainPassword, passwordHash) {
    return bcrypt.compare(plainPassword, passwordHash);
  }

  issueToken(user) {
    return jwt.sign(
      { id: user._id.toString(), role: user.role },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );
  }

  verifyToken(token) {
    return jwt.verify(token, this.jwtSecret);
  }

  // Short-lived token handed out after the password step of a 2FA login. It is
  // signed with a DIFFERENT key from session tokens, so it can never be used
  // to call the API — it only proves "this person already passed the password".
  issueChallengeToken(user) {
    return jwt.sign(
      { id: user._id.toString(), purpose: '2fa' },
      this.jwtSecret + ':2fa-challenge',
      { expiresIn: '5m' }
    );
  }

  verifyChallengeToken(token) {
    const decoded = jwt.verify(token, this.jwtSecret + ':2fa-challenge');
    if (decoded.purpose !== '2fa') throw new Error('Wrong token type');
    return decoded;
  }
}

// Freeze the single shared instance — every file that requires this module
// gets the same object back (Node's module cache already gives us this,
// but the constructor guard makes the intent explicit).
module.exports = new AuthService();
__SAFEREACH_EOF__
echo "  wrote services/AuthService.js"
cat > services/TotpService.js << '__SAFEREACH_EOF__'
// services/TotpService.js
// Time-based one-time passwords (RFC 6238) for coordinator/admin 2FA, built on
// Node's built-in crypto — no extra packages to install. Works with Google
// Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS and similar apps.
const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

// HOTP (RFC 4226): HMAC-SHA1 of the counter, dynamically truncated.
function hotp(key, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

const safeEqual = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

class TotpService {
  generateSecret() {
    return base32Encode(crypto.randomBytes(20)); // 160-bit secret, 32 base32 chars
  }

  codeAt(secretB32, timeMs = Date.now()) {
    return hotp(base32Decode(secretB32), Math.floor(timeMs / 1000 / STEP_SECONDS));
  }

  // Returns the matching 30-second step number, or null. Accepts one step
  // either side of "now" to tolerate clock drift between phone and server.
  matchStep(secretB32, code, timeMs = Date.now(), window = 1) {
    if (!/^\d{6}$/.test(String(code))) return null;
    const key = base32Decode(secretB32);
    const now = Math.floor(timeMs / 1000 / STEP_SECONDS);
    let found = null;
    for (let d = -window; d <= window; d++) {
      if (now + d < 0) continue; // no time step exists before 1970
      if (safeEqual(hotp(key, now + d), String(code)) && found === null) found = now + d;
    }
    return found;
  }

  otpauthUrl(secretB32, account, issuer = 'SafeReach') {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
  }

  // ── Secrets are encrypted at rest (AES-256-GCM). The key is derived from
  // JWT_SECRET, so rotating JWT_SECRET means 2FA must be re-enrolled
  // (an admin can reset it from the dashboard).
  _key() {
    return crypto.createHash('sha256').update('safereach-totp-key:' + process.env.JWT_SECRET).digest();
  }

  encrypt(plain) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this._key(), iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.');
  }

  decrypt(stored) {
    const [iv, tag, ct] = String(stored).split('.').map(p => Buffer.from(p, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', this._key(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  }

  // One-time recovery codes for a lost phone. Only SHA-256 hashes are stored.
  generateRecoveryCodes(count = 8) {
    const plain = [], hashes = [];
    for (let i = 0; i < count; i++) {
      const raw = crypto.randomBytes(5).toString('hex'); // 10 hex chars
      plain.push(raw.slice(0, 5) + '-' + raw.slice(5));
      hashes.push(this.hashRecovery(raw));
    }
    return { plain, hashes };
  }

  hashRecovery(code) {
    return crypto.createHash('sha256').update(String(code).replace(/[\s-]/g, '').toLowerCase()).digest('hex');
  }
}

module.exports = new TotpService();
module.exports._internals = { base32Encode, base32Decode, hotp };
__SAFEREACH_EOF__
echo "  wrote services/TotpService.js"
cat > server.js << '__SAFEREACH_EOF__'
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
__SAFEREACH_EOF__
echo "  wrote server.js"
cat > tests/README.md << '__SAFEREACH_EOF__'
# Automated tests

Run everything with:

```
npm test
```

CircleCI runs the same command on every push to `main` (see `.circleci/config.yml`).
The tests use Node's built-in test runner — no extra packages needed.

## How they work

Most tests start the **real** Express app (`server.js`: the real middleware, routes,
JWT, bcrypt and error handler) on a random port and talk to it over HTTP. Only the
data layer is swapped for in-memory fakes (`tests/helpers/fakes.js`), which is what the
repository pattern from the Task 1 design makes possible — so no MongoDB connection
or `.env` file is needed.

| File | What it covers |
|---|---|
| `validators.test.js` | Whitelist input validation (patterns, required fields, bad ids, arrays/objects) |
| `totp.test.js` | 2FA maths against the official RFC 4226 / RFC 6238 test vectors, secret encryption, recovery codes |
| `auth.api.test.js` | Register, login, password change, session revocation, deactivated accounts |
| `members.api.test.js` | Check-ins, SOS alerts, incident reports, role separation |
| `coordinator.api.test.js` | Dashboard, resolving alerts, reviewing incidents, the check-in sweeper |
| `admin.api.test.js` | Accounts, roles, branches, deactivate/reactivate, password reset |
| `twofactor.api.test.js` | Two-step login, recovery codes, replay and brute-force protection, resets |
| `errors.api.test.js` | Malformed input and internal failures never crash the server or leak internals |
| `models.test.js` | Mongoose schema rules and that secrets are never serialised (needs no database) |

## Not covered

The real Mongoose queries inside `repositories/` are not exercised here — that would need
a database (for example `mongodb-memory-server`). The tests prove the API logic around them.
__SAFEREACH_EOF__
echo "  wrote tests/README.md"
cat > tests/helpers/fakes.js << '__SAFEREACH_EOF__'
// tests/helpers/fakes.js
// In-memory stand-ins for the repository layer, so the whole HTTP API can be
// tested (real Express, real routes, real middleware, real JWT + bcrypt) with
// no MongoDB connection. This is exactly what the repository pattern from the
// Task 1 design (Section 4.4) makes possible: swap the data layer, keep the API.
const path = require('path');
const Module = require('module');

const ROOT = path.join(__dirname, '..', '..');

let seq = 1;
const oid = () => (seq++).toString(16).padStart(24, '0'); // always a valid 24-char hex ObjectId

const state = { users: [], branches: [], alerts: [], incidents: [], checkIns: [], dispatched: [], failNext: new Set() };

// Lets a test make one repository method throw once, to prove the API
// survives an unexpected failure instead of crashing.
const guard = name => { if (state.failNext.delete(name)) throw new Error('simulated failure in ' + name); };

const SECRET_FIELDS = ['passwordHash', 'totpSecret', 'totpPendingSecret', 'recoveryHashes'];
const withoutSecrets = u => { const c = { ...u }; SECRET_FIELDS.forEach(f => delete c[f]); return c; };

function decorate(u) {
  if (!u) return null;
  Object.defineProperty(u, 'toSafeJSON', {
    enumerable: false, configurable: true,
    value: () => ({
      id: u._id, fullName: u.fullName, phoneNumber: u.phoneNumber, role: u.role, createdAt: u.createdAt,
      ngoBranch: u.ngoBranch || null, active: u.active !== false, twoFactorEnabled: u.totpEnabled === true,
    }),
  });
  return u;
}
const findUser = id => state.users.find(u => u._id === String(id));

const UserRepository = {
  async create(d) {
    guard('UserRepository.create');
    const u = {
      _id: oid(), createdAt: new Date(), active: true, passwordChangedAt: null, ngoBranch: null,
      totpEnabled: false, totpSecret: null, totpPendingSecret: null, recoveryHashes: [],
      totpLastStep: null, totpFailures: 0, totpLockedUntil: null, ...d,
    };
    state.users.push(u);
    return decorate(u);
  },
  async findByPhone(phoneNumber) { guard('UserRepository.findByPhone'); return decorate(state.users.find(u => u.phoneNumber === phoneNumber) || null); },
  async findById(id) { return decorate(findUser(id) || null); },
  async findByIdWith2FA(id) { return decorate(findUser(id) || null); },
  async findCoordinatorsByBranch(b) { return state.users.filter(u => u.role === 'coordinator' && u.ngoBranch === b); },
  async updateRole(id, role) { findUser(id).role = role; return decorate(findUser(id)); },
  async setActive(id, active) { findUser(id).active = active; return decorate(findUser(id)); },
  async setBranch(id, branchId) { findUser(id).ngoBranch = branchId; return decorate(findUser(id)); },
  async updatePassword(id, passwordHash) { const u = findUser(id); u.passwordHash = passwordHash; u.passwordChangedAt = new Date(); return decorate(u); },
  async list({ role } = {}) { return state.users.filter(u => !role || u.role === role).map(withoutSecrets); },
  async setPendingSecret(id, s) { findUser(id).totpPendingSecret = s; },
  async enableTotp(id, secret, hashes, step) {
    Object.assign(findUser(id), { totpEnabled: true, totpSecret: secret, totpPendingSecret: null, recoveryHashes: hashes, totpLastStep: step, totpFailures: 0, totpLockedUntil: null });
  },
  async disableTotp(id, { revokeSessions = false } = {}) {
    const u = findUser(id);
    Object.assign(u, { totpEnabled: false, totpSecret: null, totpPendingSecret: null, recoveryHashes: [], totpLastStep: null, totpFailures: 0, totpLockedUntil: null });
    if (revokeSessions) u.passwordChangedAt = new Date();
  },
  async claimTotpStep(id, step) { const u = findUser(id); if (u.totpLastStep === null || u.totpLastStep < step) { u.totpLastStep = step; return true; } return false; },
  async consumeRecoveryHash(id, hash) { const u = findUser(id); const i = u.recoveryHashes.indexOf(hash); if (i < 0) return false; u.recoveryHashes.splice(i, 1); return true; },
  async resetTotpFailures(id) { const u = findUser(id); u.totpFailures = 0; u.totpLockedUntil = null; },
  async recordTotpFailure(id, limit, lockMs) {
    const u = findUser(id); u.totpFailures += 1;
    if (u.totpFailures >= limit) { u.totpFailures = 0; u.totpLockedUntil = new Date(Date.now() + lockMs); return true; }
    return false;
  },
};

const BranchRepository = {
  async list() { return [...state.branches].sort((a, b) => a.branchName.localeCompare(b.branchName)); },
  async findById(id) { return state.branches.find(b => b._id === String(id)) || null; },
  async findByName(name) { return state.branches.find(b => b.branchName === name) || null; },
  async create(d) { const b = { _id: oid(), ...d }; state.branches.push(b); return b; },
};

const populate = userId => { const u = findUser(userId); return u ? { _id: u._id, fullName: u.fullName, phoneNumber: u.phoneNumber } : null; };

const SOSAlertRepository = {
  async create(d) {
    const a = { _id: oid(), status: 'active', triggeredAt: new Date(), resolvedBy: null, resolvedAt: null, ...d };
    state.alerts.push(a); return a;
  },
  async findById(id) { return state.alerts.find(a => a._id === String(id)) || null; },
  async findActive() { return state.alerts.filter(a => a.status === 'active').map(a => ({ ...a, userId: populate(a.userId) })); },
  async resolve(id, by) {
    const a = state.alerts.find(x => x._id === String(id)); if (!a) return null;
    Object.assign(a, { status: 'resolved', resolvedBy: by, resolvedAt: new Date() }); return a;
  },
};

const IncidentRepository = {
  async create(d) { const i = { _id: oid(), reportedAt: new Date(), reviewedBy: null, ...d }; state.incidents.push(i); return i; },
  async findAll({ limit = 50 } = {}) { return state.incidents.slice(-limit).reverse().map(i => ({ ...i, userId: populate(i.userId) })); },
  async findByUser(userId) { return state.incidents.filter(i => String(i.userId) === String(userId)); },
  async markReviewed(id, by) { const i = state.incidents.find(x => x._id === String(id)); if (!i) return null; i.reviewedBy = by; return i; },
};

const CheckInRepository = {
  async create(d) { const c = { _id: oid(), status: 'active', startTime: new Date(), ...d }; state.checkIns.push(c); return c; },
  async findById(id) { return state.checkIns.find(c => c._id === String(id)) || null; },
  async findActiveForUser(userId) { return state.checkIns.find(c => String(c.userId) === String(userId) && c.status === 'active') || null; },
  async markSafe(id) { const c = state.checkIns.find(x => x._id === String(id)); c.status = 'safe'; return c; },
  async extend(id, minutes) { const c = state.checkIns.find(x => x._id === String(id)); c.expiresAt = new Date(c.expiresAt.getTime() + minutes * 60000); return c; },
  async findAllExpiredActive() { return state.checkIns.filter(c => c.status === 'active' && c.expiresAt <= new Date()); },
  async markEscalated(id) { state.checkIns.find(x => x._id === String(id)).status = 'escalated'; },
};

const NotificationDispatcher = { dispatchAlert: async alert => { state.dispatched.push(alert); } };

function reset() {
  for (const k of ['users', 'branches', 'alerts', 'incidents', 'checkIns', 'dispatched']) state[k].length = 0;
  state.failNext.clear();
}

// Replace modules in Node's require cache so the real route code receives the
// fakes (and third-party pieces we don't want hitting the network/DB).
function replaceModule(resolvedFile, exports) {
  const m = new Module(resolvedFile, null);
  m.filename = resolvedFile; m.loaded = true; m.exports = exports;
  require.cache[resolvedFile] = m;
}
const projectFile = rel => require.resolve(path.join(ROOT, rel));
const packageFile = name => require.resolve(name, { paths: [ROOT] });

function installAll() {
  replaceModule(projectFile('repositories/UserRepository'), UserRepository);
  replaceModule(projectFile('repositories/BranchRepository'), BranchRepository);
  replaceModule(projectFile('repositories/SOSAlertRepository'), SOSAlertRepository);
  replaceModule(projectFile('repositories/IncidentRepository'), IncidentRepository);
  replaceModule(projectFile('repositories/CheckInRepository'), CheckInRepository);
  replaceModule(projectFile('services/NotificationDispatcher'), NotificationDispatcher);
  replaceModule(projectFile('config/db'), async () => {});
  // The real rate limiters would start rejecting tests after 10 logins from
  // 127.0.0.1; they are a library concern, not something we are testing here.
  replaceModule(packageFile('express-rate-limit'), () => (req, res, next) => next());
}

module.exports = { state, reset, installAll, UserRepository, BranchRepository, ROOT };
__SAFEREACH_EOF__
echo "  wrote tests/helpers/fakes.js"
cat > tests/helpers/setup.js << '__SAFEREACH_EOF__'
// tests/helpers/setup.js — require this FIRST in every API test file.
// Sets the environment, swaps in the fakes, then loads the REAL server.js
// (the actual middleware stack, routes and error handler).
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-only-secret-not-used-anywhere-else';
process.env.JWT_EXPIRES_IN = '1h';
process.env.BCRYPT_ROUNDS = '4'; // fast hashing for tests; production uses 12
delete process.env.CORS_ORIGIN;

const fakes = require('./fakes');
fakes.installAll();

const jwt = require('jsonwebtoken');
const AuthService = require('../../services/AuthService');
const TotpService = require('../../services/TotpService');

let phoneSeq = 1;
const nextPhone = () => '+2782000' + String(phoneSeq++).padStart(4, '0');

async function addUser({ role = 'member', password = 'Passw0rd!', name = 'Test Person', phone } = {}) {
  const user = await fakes.UserRepository.create({
    fullName: name, phoneNumber: phone || nextPhone(), role,
    passwordHash: await AuthService.hashPassword(password),
  });
  return { user, password, phone: user.phoneNumber, token: AuthService.issueToken(user) };
}

// A session token issued `secondsAgo` seconds in the past (to prove that
// sessions older than a password change/reset are revoked).
function oldToken(user, secondsAgo = 120) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role, iat: Math.floor(Date.now() / 1000) - secondsAgo },
    process.env.JWT_SECRET, { expiresIn: '1h' });
}

async function startApp() {
  const app = require('../../server');
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function api(method, urlPath, { token, body, raw } = {}) {
    const headers = {};
    if (token) headers.Authorization = 'Bearer ' + token;
    let payload;
    if (raw !== undefined) { payload = raw; headers['Content-Type'] = 'application/json'; }
    else if (body !== undefined) { payload = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    const res = await fetch(base + urlPath, { method, headers, body: payload });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON body */ }
    return { status: res.status, body: data };
  }
  const close = () => new Promise(resolve => {
    if (server.closeAllConnections) server.closeAllConnections();
    server.close(() => resolve());
  });
  return { api, close };
}

module.exports = { fakes, state: fakes.state, AuthService, TotpService, addUser, oldToken, startApp };
__SAFEREACH_EOF__
echo "  wrote tests/helpers/setup.js"
cat > tests/validators.test.js << '__SAFEREACH_EOF__'
// Unit tests for the whitelist validators (middleware/validators.js).
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { isValid, validateBody, validateParams } = require('../middleware/validators');

// Minimal stand-ins for Express's req/res so the middleware can run on its own.
function run(mw, req) {
  const out = { status: null, body: null, nexted: false };
  const res = { status(c) { out.status = c; return res; }, json(b) { out.body = b; return res; } };
  mw(req, res, () => { out.nexted = true; });
  return out;
}

describe('isValid', () => {
  it('accepts well-formed values', () => {
    assert.ok(isValid('fullName', "Thabo O'Neil-Smith"));
    assert.ok(isValid('phoneNumber', '+27821234567'));
    assert.ok(isValid('password', 'Test@1234'));
    assert.ok(isValid('latLng', '-26.204100'));
    assert.ok(isValid('latLng', -26.2041));
    assert.ok(isValid('mongoId', 'a'.repeat(24)));
    assert.ok(isValid('branchName', 'Thuso Soweto (North)'));
  });

  it('rejects malformed values', () => {
    assert.ok(!isValid('fullName', 'J4ne'));
    assert.ok(!isValid('fullName', '<script>'));
    assert.ok(!isValid('phoneNumber', '12'));
    assert.ok(!isValid('phoneNumber', '+27 82 123'));
    assert.ok(!isValid('latLng', '-26'), 'needs a decimal point');
    assert.ok(!isValid('latLng', '1.12345678901'), 'max 10 decimals');
    assert.ok(!isValid('mongoId', 'not-an-id'));
    assert.ok(!isValid('description', 'bad: colon'), 'colon is not whitelisted');
  });

  it('enforces the password rules', () => {
    assert.ok(!isValid('password', 'Sh0rt!'), 'too short');
    assert.ok(!isValid('password', 'alllowercase1!'), 'needs a capital');
    assert.ok(!isValid('password', 'NoNumber!!'), 'needs a digit');
    assert.ok(!isValid('password', 'NoSymbol123'), 'needs a symbol');
    assert.ok(!isValid('password', 'Aa1@' + 'x'.repeat(70)), 'over 72 characters');
  });

  it('rejects null, undefined, arrays and objects outright', () => {
    for (const bad of [null, undefined, ['+27821234567'], { a: 1 }, true]) {
      assert.ok(!isValid('phoneNumber', bad), String(JSON.stringify(bad)));
    }
  });
});

describe('validateBody', () => {
  const mw = validateBody({ fullName: 'fullName', phoneNumber: 'phoneNumber' }, ['fullName', 'phoneNumber']);

  it('passes a valid body through', () => {
    const r = run(mw, { body: { fullName: 'Jane Doe', phoneNumber: '+27821234567' } });
    assert.equal(r.nexted, true);
  });

  it('returns 400 for a missing required field', () => {
    const r = run(mw, { body: { fullName: 'Jane Doe' } });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /phoneNumber/);
  });

  it('treats null and empty string as missing', () => {
    assert.equal(run(mw, { body: { fullName: 'Jane Doe', phoneNumber: null } }).status, 400);
    assert.equal(run(mw, { body: { fullName: '', phoneNumber: '+27821234567' } }).status, 400);
  });

  it('returns 400 for an invalid field', () => {
    const r = run(mw, { body: { fullName: 'J4ne', phoneNumber: '+27821234567' } });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /fullName/);
  });

  it('rejects a body that is not a JSON object', () => {
    assert.equal(run(mw, { body: undefined }).status, 400);
    assert.equal(run(mw, { body: [] }).status, 400);
    assert.equal(run(mw, { body: 'text' }).status, 400);
  });

  it('skips optional fields that are absent but validates them when present', () => {
    const optional = validateBody({ destination: 'destination' });
    assert.equal(run(optional, { body: {} }).nexted, true);
    assert.equal(run(optional, { body: { destination: 'Sandton' } }).nexted, true);
    assert.equal(run(optional, { body: { destination: 'bad: colon' } }).status, 400);
  });
});

describe('validateParams', () => {
  const mw = validateParams({ id: 'mongoId' });
  it('accepts a valid id', () => assert.equal(run(mw, { params: { id: 'a'.repeat(24) } }).nexted, true));
  it('rejects an invalid id with 400', () => assert.equal(run(mw, { params: { id: 'nope' } }).status, 400));
});
__SAFEREACH_EOF__
echo "  wrote tests/validators.test.js"
cat > tests/totp.test.js << '__SAFEREACH_EOF__'
// Unit tests for the 2FA building blocks (services/TotpService.js), checked
// against the official RFC 4226 / RFC 6238 test vectors.
process.env.JWT_SECRET = 'test-only-secret-not-used-anywhere-else';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Totp = require('../services/TotpService');
const { base32Encode, base32Decode, hotp } = Totp._internals;

// The RFC test secret is the ASCII string "12345678901234567890".
const RFC_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('base32', () => {
  it('encodes the RFC test secret', () => {
    assert.equal(base32Encode(Buffer.from('12345678901234567890')), RFC_SECRET_B32);
  });
  it('round-trips random secrets', () => {
    for (let i = 0; i < 20; i++) {
      const s = Totp.generateSecret();
      assert.equal(s.length, 32);
      assert.match(s, /^[A-Z2-7]+$/);
      assert.equal(base32Encode(base32Decode(s)), s);
    }
  });
  it('rejects characters outside the alphabet', () => {
    assert.throws(() => base32Decode('NOT-VALID-1'));
  });
});

describe('HOTP / TOTP vectors', () => {
  it('RFC 4226 HOTP, counter 0', () => {
    assert.equal(hotp(Buffer.from('12345678901234567890'), 0), '755224');
  });
  it('RFC 6238 at T=59s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 59000), '287082'));
  it('RFC 6238 at T=1111111109s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 1111111109000), '081804'));
  it('RFC 6238 at T=1234567890s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 1234567890000), '005924'));
});

describe('matchStep', () => {
  const t = 59000;
  it('returns the step for the current code', () => assert.equal(Totp.matchStep(RFC_SECRET_B32, '287082', t), 1));
  it('tolerates one step of clock drift either way', () => {
    assert.notEqual(Totp.matchStep(RFC_SECRET_B32, '287082', t + 30000), null);
    assert.notEqual(Totp.matchStep(RFC_SECRET_B32, '287082', t - 30000), null);
  });
  it('rejects codes two or more steps away', () => assert.equal(Totp.matchStep(RFC_SECRET_B32, '287082', t + 90000), null));
  it('rejects wrong, short and non-numeric codes', () => {
    assert.equal(Totp.matchStep(RFC_SECRET_B32, '000000', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, '123', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, 'abcdef', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, undefined, t), null);
  });
});

describe('secret encryption', () => {
  it('encrypts and decrypts', () => {
    const enc = Totp.encrypt('SECRETVALUE');
    assert.notEqual(enc, 'SECRETVALUE');
    assert.equal(Totp.decrypt(enc), 'SECRETVALUE');
  });
  it('uses a fresh IV each time', () => assert.notEqual(Totp.encrypt('same'), Totp.encrypt('same')));
  it('rejects tampered ciphertext', () => {
    const parts = Totp.encrypt('SECRETVALUE').split('.');
    parts[2] = Buffer.from('tampered-bytes').toString('base64');
    assert.throws(() => Totp.decrypt(parts.join('.')));
  });
});

describe('recovery codes and setup link', () => {
  it('generates 8 unique codes and stores only hashes', () => {
    const { plain, hashes } = Totp.generateRecoveryCodes(8);
    assert.equal(plain.length, 8);
    assert.equal(new Set(plain).size, 8);
    plain.forEach((c, i) => {
      assert.match(c, /^[a-f0-9]{5}-[a-f0-9]{5}$/);
      assert.equal(hashes[i], Totp.hashRecovery(c));
      assert.ok(!hashes[i].includes(c.replace('-', '')));
    });
  });
  it('hashing ignores case and the dash', () => {
    assert.equal(Totp.hashRecovery('ABCDE-12345'), Totp.hashRecovery('abcde12345'));
  });
  it('builds an otpauth:// URL authenticator apps understand', () => {
    const url = Totp.otpauthUrl('JBSWY3DPEHPK3PXP', '+27110000002');
    assert.ok(url.startsWith('otpauth://totp/SafeReach%3A%2B27110000002?'));
    assert.match(url, /secret=JBSWY3DPEHPK3PXP/);
    assert.match(url, /digits=6/);
    assert.match(url, /period=30/);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/totp.test.js"
cat > tests/auth.api.test.js << '__SAFEREACH_EOF__'
// Member registration, login, password change and session handling — over real HTTP.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const register = body => app.api('POST', '/api/auth/register', { body });
const login = (phoneNumber, password) => app.api('POST', '/api/auth/login', { body: { phoneNumber, password } });

describe('POST /api/auth/register', () => {
  const good = { fullName: 'Jane Doe', phoneNumber: '+27821230001', password: 'Passw0rd!' };

  it('creates a member and returns a token, never the password hash', async () => {
    const r = await register(good);
    assert.equal(r.status, 201);
    assert.ok(r.body.token);
    assert.equal(r.body.user.role, 'member');
    assert.ok(!JSON.stringify(r.body).includes('passwordHash'));
    assert.ok(!JSON.stringify(r.body).includes('Passw0rd!'));
  });

  it('stores a bcrypt hash (using the configured cost), never the plain password', async () => {
    await register(good);
    const stored = fakes.state.users[0].passwordHash;
    assert.match(stored, /^\$2[aby]\$04\$[./A-Za-z0-9]{53}$/); // 04 = BCRYPT_ROUNDS set by the test setup
    assert.ok(!stored.includes(good.password));
  });

  it('rejects a duplicate phone number with 409', async () => {
    await register(good);
    assert.equal((await register(good)).status, 409);
  });

  it('rejects weak passwords, bad names and bad numbers with 400', async () => {
    assert.equal((await register({ ...good, password: 'weak' })).status, 400);
    assert.equal((await register({ ...good, fullName: 'J4ne' })).status, 400);
    assert.equal((await register({ ...good, phoneNumber: '12' })).status, 400);
  });

  it('rejects a missing password with 400 instead of crashing', async () => {
    const r = await register({ fullName: 'Jane Doe', phoneNumber: '+27821230002' });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /password/);
  });

  it('rejects array / object values with 400', async () => {
    assert.equal((await register({ ...good, phoneNumber: ['+27821230003'] })).status, 400);
    assert.equal((await register({ ...good, fullName: { $ne: 1 } })).status, 400);
  });
});

describe('POST /api/auth/login', () => {
  it('signs a member in', async () => {
    const { phone, password } = await addUser();
    const r = await login(phone, password);
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
  });

  it('gives the same 401 for a wrong password and an unknown number', async () => {
    const { phone } = await addUser();
    const wrong = await login(phone, 'Wrong@1234');
    const unknown = await login('+27829999999', 'Passw0rd!');
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.deepEqual(wrong.body, unknown.body);
  });

  it('rejects non-string passwords with 400', async () => {
    const { phone } = await addUser();
    assert.equal((await login(phone, { $ne: 1 })).status, 400);
    assert.equal((await login(phone, 12345678)).status, 400);
    assert.equal((await login(phone, undefined)).status, 400);
  });

  it('does not let coordinators or admins in through the member login', async () => {
    const coord = await addUser({ role: 'coordinator' });
    const admin = await addUser({ role: 'admin' });
    for (const u of [coord, admin]) {
      const r = await login(u.phone, u.password);
      assert.equal(r.status, 401);
      assert.ok(!r.body.token);
    }
  });

  it('says a deactivated account is deactivated only after the right password', async () => {
    const { user, phone, password } = await addUser();
    user.active = false;
    assert.equal((await login(phone, password)).status, 403);
    assert.equal((await login(phone, 'Wrong@1234')).status, 401);
  });
});

describe('session handling', () => {
  it('rejects requests with no token, a garbage token, or a deleted user', async () => {
    assert.equal((await app.api('GET', '/api/checkin/active')).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: 'garbage' })).status, 401);
    const { token } = await addUser();
    fakes.state.users.length = 0;
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 401);
  });

  it('stops honouring the token of a deactivated account', async () => {
    const { user, token } = await addUser();
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 200);
    user.active = false;
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 401);
  });

  it('rejects a token signed with a different secret', async () => {
    const jwt = require('jsonwebtoken');
    const { user } = await addUser();
    const forged = jwt.sign({ id: user._id, role: 'member' }, 'some-other-secret', { expiresIn: '1h' });
    assert.equal((await app.api('GET', '/api/checkin/active', { token: forged })).status, 401);
  });
});

describe('PATCH /api/auth/password', () => {
  const change = (token, currentPassword, newPassword) =>
    app.api('PATCH', '/api/auth/password', { token, body: { currentPassword, newPassword } });

  it('changes the password and returns a fresh token', async () => {
    const { phone, password, token } = await addUser();
    const r = await change(token, password, 'NewPass@999');
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
    assert.equal((await login(phone, password)).status, 401, 'old password no longer works');
    assert.equal((await login(phone, 'NewPass@999')).status, 200, 'new password works');
  });

  it('signs out sessions issued before the change but keeps the new one', async () => {
    const { user, password, token } = await addUser();
    const stale = oldToken(user, 120);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 200);
    const r = await change(token, password, 'NewPass@999');
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: r.body.token })).status, 200);
  });

  it('answers 400 (not 401) for a wrong current password so clients do not log out', async () => {
    const { token } = await addUser();
    assert.equal((await change(token, 'Wrong@1234', 'NewPass@999')).status, 400);
  });

  it('rejects an unchanged, weak, missing or non-string new password', async () => {
    const { password, token } = await addUser();
    assert.equal((await change(token, password, password)).status, 400);
    assert.equal((await change(token, password, 'weak')).status, 400);
    assert.equal((await app.api('PATCH', '/api/auth/password', { token, body: { currentPassword: password } })).status, 400);
    assert.equal((await change(token, ['x'], 'NewPass@999')).status, 400);
  });

  it('needs a signed-in user', async () => {
    const r = await app.api('PATCH', '/api/auth/password', { body: { currentPassword: 'a', newPassword: 'NewPass@999' } });
    assert.equal(r.status, 401);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/auth.api.test.js"
cat > tests/members.api.test.js << '__SAFEREACH_EOF__'
// What a signed-in member can do: check-ins, SOS alerts and incident reports.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

describe('check-ins', () => {
  const start = (token, body) => app.api('POST', '/api/checkin', { token, body });

  it('starts a check-in with the right expiry', async () => {
    const { token } = await addUser();
    const before = Date.now();
    const r = await start(token, { durationMinutes: 15, destination: 'Sandton', lat: '-26.204100', lng: '28.047300' });
    assert.equal(r.status, 201);
    assert.equal(r.body.checkIn.status, 'active');
    const expires = new Date(r.body.checkIn.expiresAt).getTime();
    assert.ok(Math.abs(expires - (before + 15 * 60000)) < 5000);
  });

  it('allows only one active check-in at a time (409)', async () => {
    const { token } = await addUser();
    assert.equal((await start(token, { durationMinutes: 15 })).status, 201);
    assert.equal((await start(token, { durationMinutes: 30 })).status, 409);
  });

  it('GET /active returns the current check-in, or null', async () => {
    const { token } = await addUser();
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).body.checkIn, null);
    await start(token, { durationMinutes: 15 });
    assert.ok((await app.api('GET', '/api/checkin/active', { token })).body.checkIn);
  });

  it('rejects bad durations and coordinates with 400', async () => {
    const { token } = await addUser();
    for (const body of [
      {}, { durationMinutes: 1 }, { durationMinutes: 99999 }, { durationMinutes: 'soon' },
      { durationMinutes: [15] }, { durationMinutes: { a: 1 } },
      { durationMinutes: 15, lat: '-26' }, { durationMinutes: 15, destination: 'bad: colon' },
    ]) {
      assert.equal((await start(token, body)).status, 400, JSON.stringify(body));
    }
  });

  it('extends and ends a check-in', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    const ext = await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 15 } });
    assert.equal(ext.status, 200);
    assert.equal(new Date(ext.body.checkIn.expiresAt) - new Date(checkIn.expiresAt), 15 * 60000);
    const safe = await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal(safe.body.checkIn.status, 'safe');
  });

  it('refuses silly extensions and extending a finished check-in', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    for (const minutes of [-50, 0, 100000, 'abc', [5]]) {
      assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes } })).status, 400, String(minutes));
    }
    await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 15 } })).status, 409);
  });

  it('rejects malformed ids with 400 and other people\'s check-ins with 404', async () => {
    const a = await addUser(), b = await addUser();
    const { body: { checkIn } } = await start(a.token, { durationMinutes: 15 });
    assert.equal((await app.api('PATCH', '/api/checkin/not-an-id/safe', { token: a.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token: b.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token: b.token, body: { minutes: 5 } })).status, 404);
  });
});

describe('SOS alerts', () => {
  const sos = (token, body) => app.api('POST', '/api/sos', { token, body });

  it('creates an active alert and notifies coordinators', async () => {
    const { token } = await addUser();
    const r = await sos(token, { triggerSource: 'manual', lat: '-26.204100', lng: '28.047300' });
    assert.equal(r.status, 201);
    assert.equal(r.body.status, 'active');
    assert.equal(state.alerts.length, 1);
    assert.equal(state.dispatched.length, 1);
    assert.equal(state.dispatched[0]._id, r.body.alertId);
  });

  it('accepts shake and defaults unknown sources to manual', async () => {
    const { token } = await addUser();
    await sos(token, { triggerSource: 'shake' });
    await sos(token, { triggerSource: 'made-up' });
    assert.deepEqual(state.alerts.map(a => a.triggerSource), ['shake', 'manual']);
  });

  it('works with no body at all (location unknown)', async () => {
    const { token } = await addUser();
    assert.equal((await sos(token, {})).status, 201);
  });

  it('rejects bad coordinates and bad check-in ids with 400', async () => {
    const { token } = await addUser();
    for (const body of [{ lat: '-26' }, { lng: 'abc' }, { checkInId: 'nope' }, { checkInId: ['x'] }, { checkInId: { a: 1 } }]) {
      assert.equal((await sos(token, body)).status, 400, JSON.stringify(body));
    }
    assert.equal(state.alerts.length, 0);
  });

  it('is members-only and needs a session', async () => {
    const coord = await addUser({ role: 'coordinator' });
    assert.equal((await sos(coord.token, {})).status, 403);
    assert.equal((await sos(undefined, {})).status, 401);
  });
});

describe('incident reports', () => {
  const report = (token, body) => app.api('POST', '/api/incidents', { token, body });
  const good = { type: 'theft', description: 'A briefcase was stolen', severity: 'high', location: 'Main Rd', lat: '-26.033682', lng: '27.971534' };

  it('creates a report', async () => {
    const { token } = await addUser();
    const r = await report(token, good);
    assert.equal(r.status, 201);
    assert.equal(r.body.incident.severity, 'high');
  });

  it('defaults an unknown severity to medium', async () => {
    const { token } = await addUser();
    assert.equal((await report(token, { ...good, severity: 'extreme' })).body.incident.severity, 'medium');
  });

  it('rejects missing or invalid fields with 400', async () => {
    const { token } = await addUser();
    for (const body of [
      { type: 'theft' }, { description: 'no type' }, { ...good, type: 'alien-invasion' },
      { ...good, description: 'has: a colon' }, { ...good, description: ['x'] }, { ...good, lat: '-26' },
    ]) {
      assert.equal((await report(token, body)).status, 400, JSON.stringify(body));
    }
  });

  it('lists only the member\'s own reports', async () => {
    const a = await addUser(), b = await addUser();
    await report(a.token, good);
    await report(b.token, { ...good, description: 'Someone else report' });
    const mine = await app.api('GET', '/api/incidents/mine', { token: a.token });
    assert.equal(mine.body.length, 1);
    assert.equal(mine.body[0].description, 'A briefcase was stolen');
  });
});

describe('role separation', () => {
  it('keeps members out of the coordinator and admin areas', async () => {
    const { token } = await addUser();
    for (const p of ['/api/coordinator/dashboard', '/api/coordinator/members', '/api/admin/users', '/api/admin/branches']) {
      assert.equal((await app.api('GET', p, { token })).status, 403, p);
    }
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/members.api.test.js"
cat > tests/coordinator.api.test.js << '__SAFEREACH_EOF__'
// The coordinator dashboard: live alerts, incident review, members, and the
// server-side check-in sweeper that escalates missed check-ins.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

describe('coordinator dashboard', () => {
  it('shows active alerts with the member\'s name and number, plus recent incidents', async () => {
    const member = await addUser({ name: 'Test User' });
    const coord = await addUser({ role: 'coordinator' });
    await app.api('POST', '/api/sos', { token: member.token, body: { lat: '-26.204100', lng: '28.047300' } });
    await app.api('POST', '/api/incidents', { token: member.token, body: { type: 'theft', description: 'Bag stolen' } });

    const r = await app.api('GET', '/api/coordinator/dashboard', { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.activeAlerts.length, 1);
    assert.equal(r.body.activeAlerts[0].userId.fullName, 'Test User');
    assert.equal(r.body.activeAlerts[0].userId.phoneNumber, member.phone);
    assert.equal(r.body.recentIncidents.length, 1);
  });

  it('is open to admins and closed to everyone signed out', async () => {
    const admin = await addUser({ role: 'admin' });
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: admin.token })).status, 200);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard')).status, 401);
  });

  it('lists members only (not coordinators or admins) and never their password hashes', async () => {
    await addUser({ name: 'Member One' });
    await addUser({ role: 'admin' });
    const coord = await addUser({ role: 'coordinator' });
    const r = await app.api('GET', '/api/coordinator/members', { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.length, 1);
    assert.equal(r.body[0].fullName, 'Member One');
    assert.ok(!JSON.stringify(r.body).includes('passwordHash'));
  });
});

describe('resolving alerts and reviewing incidents', () => {
  it('a coordinator can resolve an alert, and it leaves the active list', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    const { body: { alertId } } = await app.api('POST', '/api/sos', { token: member.token, body: {} });

    const r = await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.alert.status, 'resolved');
    assert.equal(r.body.alert.resolvedBy, coord.user._id);
    const dash = await app.api('GET', '/api/coordinator/dashboard', { token: coord.token });
    assert.equal(dash.body.activeAlerts.length, 0);
  });

  it('rejects bad ids (400), unknown ids (404) and members (403)', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('PATCH', '/api/sos/zzz/resolve', { token: coord.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/sos/${'f'.repeat(24)}/resolve`, { token: coord.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/sos/${'f'.repeat(24)}/resolve`, { token: member.token })).status, 403);
  });

  it('a coordinator can mark an incident reviewed', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    const { body: { incident } } = await app.api('POST', '/api/incidents', { token: member.token, body: { type: 'fire', description: 'Shack fire' } });
    const r = await app.api('PATCH', `/api/incidents/${incident._id}/review`, { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.incident.reviewedBy, coord.user._id);
    assert.equal((await app.api('PATCH', '/api/incidents/bad/review', { token: coord.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/incidents/${'f'.repeat(24)}/review`, { token: coord.token })).status, 404);
  });
});

describe('CheckInSweeper', () => {
  const sweeper = require('../services/CheckInSweeper');
  const origLog = console.log;
  before(() => { console.log = () => {}; });
  after(() => { console.log = origLog; });

  it('escalates an expired, unconfirmed check-in into an alert and a high-severity incident', async () => {
    const member = await addUser();
    await fakes.state.checkIns.push({ _id: 'c'.repeat(24), userId: member.user._id, status: 'active', durationMinutes: 5, destination: 'Sandton', lat: null, lng: null, expiresAt: new Date(Date.now() - 60000) });

    await sweeper.sweepOnce();

    assert.equal(state.checkIns[0].status, 'escalated');
    assert.equal(state.alerts.length, 1);
    assert.equal(state.alerts[0].triggerSource, 'checkin_timeout');
    assert.equal(state.incidents.length, 1);
    assert.equal(state.incidents[0].severity, 'high');
    assert.match(state.incidents[0].description, /Sandton/);
    assert.equal(state.dispatched.length, 1);
  });

  it('leaves check-ins alone that are confirmed safe or not yet due, and does not escalate twice', async () => {
    const member = await addUser();
    const base = { userId: member.user._id, durationMinutes: 5, destination: 'x', lat: null, lng: null };
    state.checkIns.push({ ...base, _id: 'a'.repeat(24), status: 'safe', expiresAt: new Date(Date.now() - 60000) });
    state.checkIns.push({ ...base, _id: 'b'.repeat(24), status: 'active', expiresAt: new Date(Date.now() + 600000) });
    state.checkIns.push({ ...base, _id: 'd'.repeat(24), status: 'active', expiresAt: new Date(Date.now() - 1000) });

    await sweeper.sweepOnce();
    await sweeper.sweepOnce();

    assert.equal(state.alerts.length, 1, 'only the one overdue check-in escalates, once');
    assert.equal(state.checkIns.find(c => c._id === 'a'.repeat(24)).status, 'safe');
    assert.equal(state.checkIns.find(c => c._id === 'b'.repeat(24)).status, 'active');
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/coordinator.api.test.js"
cat > tests/admin.api.test.js << '__SAFEREACH_EOF__'
// Admin tools: accounts, roles, branches, deactivation, password and 2FA resets.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, AuthService, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const newCoordinator = { fullName: 'New Coordinator', phoneNumber: '+27820001111', password: 'Coord@1234', role: 'coordinator' };

describe('access control', () => {
  it('only admins may use /api/admin', async () => {
    const coord = await addUser({ role: 'coordinator' });
    const member = await addUser();
    for (const who of [coord, member]) {
      assert.equal((await app.api('GET', '/api/admin/users', { token: who.token })).status, 403);
      assert.equal((await app.api('POST', '/api/admin/users', { token: who.token, body: newCoordinator })).status, 403);
    }
    assert.equal((await app.api('GET', '/api/admin/users')).status, 401);
  });
});

describe('creating accounts', () => {
  it('creates a coordinator who can then sign in at the coordinator login', async () => {
    const admin = await addUser({ role: 'admin' });
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: newCoordinator });
    assert.equal(r.status, 201);
    assert.equal(r.body.user.role, 'coordinator');
    const login = await app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: newCoordinator.phoneNumber, password: newCoordinator.password } });
    assert.equal(login.status, 200);
    assert.ok(login.body.token);
  });

  it('puts a coordinator in a branch that exists, and rejects ones that do not', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'Thuso Soweto', region: 'Gauteng' } });
    const ok = await app.api('POST', '/api/admin/users', { token: admin.token, body: { ...newCoordinator, ngoBranch: branch._id } });
    assert.equal(ok.status, 201);
    assert.equal(ok.body.user.ngoBranch, branch._id);
    for (const ngoBranch of ['not-an-id', 'e'.repeat(24), ['x']]) {
      const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { ...newCoordinator, phoneNumber: '+27820002222', ngoBranch } });
      assert.equal(r.status, 400, JSON.stringify(ngoBranch));
    }
  });

  it('rejects missing password / role, bad role, weak password and duplicates', async () => {
    const admin = await addUser({ role: 'admin' });
    const post = body => app.api('POST', '/api/admin/users', { token: admin.token, body });
    const { password, ...noPassword } = newCoordinator;
    const { role, ...noRole } = newCoordinator;
    assert.equal((await post(noPassword)).status, 400, 'used to crash the server');
    assert.equal((await post(noRole)).status, 400);
    assert.equal((await post({ ...newCoordinator, role: 'superuser' })).status, 400);
    assert.equal((await post({ ...newCoordinator, password: 'weak' })).status, 400);
    assert.equal((await post(newCoordinator)).status, 201);
    assert.equal((await post(newCoordinator)).status, 409);
  });
});

describe('listing accounts', () => {
  it('never exposes password hashes or 2FA secrets', async () => {
    const admin = await addUser({ role: 'admin' });
    const coord = await addUser({ role: 'coordinator' });
    coord.user.totpSecret = 'SUPER-SECRET-VALUE';
    coord.user.recoveryHashes = ['deadbeef'];
    const r = await app.api('GET', '/api/admin/users', { token: admin.token });
    assert.equal(r.status, 200);
    const text = JSON.stringify(r.body);
    for (const leak of ['passwordHash', 'totpSecret', 'SUPER-SECRET-VALUE', 'recoveryHashes', 'deadbeef']) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
  });

  it('filters by role and rejects an invalid filter', async () => {
    const admin = await addUser({ role: 'admin' });
    await addUser({ role: 'coordinator' });
    await addUser();
    assert.equal((await app.api('GET', '/api/admin/users?role=coordinator', { token: admin.token })).body.length, 1);
    assert.equal((await app.api('GET', '/api/admin/users?role=wizard', { token: admin.token })).status, 400);
  });
});

describe('changing roles', () => {
  it('changes another account\'s role', async () => {
    const admin = await addUser({ role: 'admin' });
    const target = await addUser();
    const r = await app.api('PATCH', `/api/admin/users/${target.user._id}/role`, { token: admin.token, body: { role: 'coordinator' } });
    assert.equal(r.status, 200);
    assert.equal(target.user.role, 'coordinator');
  });

  it('will not let an admin change their own role', async () => {
    const admin = await addUser({ role: 'admin' });
    const r = await app.api('PATCH', `/api/admin/users/${admin.user._id}/role`, { token: admin.token, body: { role: 'member' } });
    assert.equal(r.status, 400);
    assert.equal(admin.user.role, 'admin');
  });

  it('validates the id, the role and the target', async () => {
    const admin = await addUser({ role: 'admin' });
    const t = await addUser();
    assert.equal((await app.api('PATCH', '/api/admin/users/nope/role', { token: admin.token, body: { role: 'member' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/role`, { token: admin.token, body: { role: 'wizard' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${'e'.repeat(24)}/role`, { token: admin.token, body: { role: 'member' } })).status, 404);
  });

  it('clears a coordinator\'s branch when they stop being a coordinator', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'North', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    c.user.ngoBranch = branch._id;
    await app.api('PATCH', `/api/admin/users/${c.user._id}/role`, { token: admin.token, body: { role: 'member' } });
    assert.equal(c.user.ngoBranch, null);
  });
});

describe('deactivating and reactivating (soft delete)', () => {
  it('blocks sign-in and kills existing sessions, then restores access', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await addUser({ role: 'coordinator' });
    const patch = active => app.api('PATCH', `/api/admin/users/${c.user._id}/active`, { token: admin.token, body: { active } });
    const login = () => app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: c.phone, password: c.password } });

    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 200);
    assert.equal((await patch(false)).body.user.active, false);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 401, 'existing session is dead');
    assert.equal((await login()).status, 403, 'right password, deactivated');
    assert.equal((await app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: c.phone, password: 'Wrong@1234' } })).status, 401, 'wrong password reveals nothing');

    assert.equal((await patch(true)).body.user.active, true);
    assert.equal((await login()).status, 200);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 200);
  });

  it('keeps the account\'s records', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    await app.api('POST', '/api/sos', { token: m.token, body: {} });
    await app.api('PATCH', `/api/admin/users/${m.user._id}/active`, { token: admin.token, body: { active: false } });
    assert.equal(state.alerts.length, 1);
    assert.equal(state.users.length, 2);
  });

  it('will not let an admin deactivate themselves, and validates input', async () => {
    const admin = await addUser({ role: 'admin' });
    const t = await addUser();
    assert.equal((await app.api('PATCH', `/api/admin/users/${admin.user._id}/active`, { token: admin.token, body: { active: false } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/active`, { token: admin.token, body: { active: 'false' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/active`, { token: admin.token, body: {} })).status, 400);
    assert.equal((await app.api('PATCH', '/api/admin/users/bad/active', { token: admin.token, body: { active: false } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${'e'.repeat(24)}/active`, { token: admin.token, body: { active: false } })).status, 404);
  });
});

describe('NGO branches', () => {
  it('creates, lists (sorted) and de-duplicates branches', async () => {
    const admin = await addUser({ role: 'admin' });
    const add = body => app.api('POST', '/api/admin/branches', { token: admin.token, body });
    assert.equal((await add({ branchName: 'Zulu Branch', region: 'KZN' })).status, 201);
    assert.equal((await add({ branchName: 'Alpha Branch', region: 'Gauteng' })).status, 201);
    assert.equal((await add({ branchName: 'Alpha Branch', region: 'Gauteng' })).status, 409);
    const list = await app.api('GET', '/api/admin/branches', { token: admin.token });
    assert.deepEqual(list.body.map(b => b.branchName), ['Alpha Branch', 'Zulu Branch']);
  });

  it('validates names and regions', async () => {
    const admin = await addUser({ role: 'admin' });
    const add = body => app.api('POST', '/api/admin/branches', { token: admin.token, body });
    assert.equal((await add({ branchName: '<script>', region: 'Gauteng' })).status, 400);
    assert.equal((await add({ branchName: 'Only Name' })).status, 400);
    assert.equal((await add({ region: 'Only Region' })).status, 400);
    assert.equal((await add({ branchName: ['x'], region: 'Gauteng' })).status, 400);
  });

  it('assigns and clears a coordinator\'s branch, but not a member\'s', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'East', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    const m = await addUser();
    const set = (id, ngoBranch) => app.api('PATCH', `/api/admin/users/${id}/branch`, { token: admin.token, body: { ngoBranch } });
    assert.equal((await set(c.user._id, branch._id)).status, 200);
    assert.equal(c.user.ngoBranch, branch._id);
    assert.equal((await set(c.user._id, null)).status, 200);
    assert.equal(c.user.ngoBranch, null);
    assert.equal((await set(m.user._id, branch._id)).status, 400);
    assert.equal((await set(c.user._id, 'e'.repeat(24))).status, 400);
    assert.equal((await set(c.user._id, 'nope')).status, 400);
  });
});

describe('resetting someone\'s password', () => {
  it('sets a temporary password and signs them out everywhere', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    const stale = oldToken(m.user, 120);
    const r = await app.api('POST', `/api/admin/users/${m.user._id}/reset-password`, { token: admin.token, body: { newPassword: 'Reset@12345' } });
    assert.equal(r.status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: m.phone, password: 'Reset@12345' } })).status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: m.phone, password: m.password } })).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 401);
  });

  it('rejects weak passwords, bad ids and self-reset', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    const reset = (id, newPassword) => app.api('POST', `/api/admin/users/${id}/reset-password`, { token: admin.token, body: { newPassword } });
    assert.equal((await reset(m.user._id, 'weak')).status, 400);
    assert.equal((await reset(m.user._id, undefined)).status, 400);
    assert.equal((await reset('nope', 'Reset@12345')).status, 400);
    assert.equal((await reset('e'.repeat(24), 'Reset@12345')).status, 404);
    assert.equal((await reset(admin.user._id, 'Reset@12345')).status, 400);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/admin.api.test.js"
cat > tests/twofactor.api.test.js << '__SAFEREACH_EOF__'
// Two-factor authentication for coordinators and admins, end to end over HTTP.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { fakes, AuthService, TotpService, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const base = '/api/coordinator/auth';
// A 6-digit code that is guaranteed NOT to be valid right now (not even for the
// neighbouring time steps), so these tests can never pass or fail by chance.
const invalidFor = secret => {
  const valid = new Set([-1, 0, 1].map(d => TotpService.codeAt(secret, Date.now() + d * 30000)));
  for (let n = 0; ; n++) { const c = String(n).padStart(6, '0'); if (!valid.has(c)) return c; }
};
const login = (phone, password) => app.api('POST', `${base}/login`, { body: { phoneNumber: phone, password } });
const verify = (challengeToken, code) => app.api('POST', `${base}/verify-2fa`, { body: { challengeToken, code } });
// "Time passes": let the next code be accepted (each 30-second code works once).
const nextStep = user => { user.totpLastStep = (user.totpLastStep || 0) - 5; };

// Turns 2FA on for a fresh account through the real endpoints.
async function enrolled(role = 'coordinator') {
  const acct = await addUser({ role });
  const setup = await app.api('POST', `${base}/2fa/setup`, { token: acct.token, body: { password: acct.password } });
  const secret = setup.body.secret;
  const enable = await app.api('POST', `${base}/2fa/enable`, { token: acct.token, body: { code: TotpService.codeAt(secret) } });
  nextStep(acct.user);
  return { ...acct, secret, recoveryCodes: enable.body.recoveryCodes };
}

describe('logging in without 2FA', () => {
  it('still gives a session straight away', async () => {
    const c = await addUser({ role: 'coordinator' });
    const r = await login(c.phone, c.password);
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
    assert.equal(r.body.requires2FA, undefined);
    assert.equal(r.body.user.twoFactorEnabled, false);
  });
});

describe('turning 2FA on', () => {
  it('needs the account password', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: 'Wrong@1234' } })).status, 400);
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: {} })).status, 400);
  });

  it('is for coordinators and admins only', async () => {
    const m = await addUser();
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: m.token, body: { password: m.password } })).status, 403);
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { body: { password: 'x' } })).status, 401);
  });

  it('returns a secret and an authenticator link, and stores the secret encrypted', async () => {
    const c = await addUser({ role: 'coordinator' });
    const r = await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } });
    assert.equal(r.status, 200);
    assert.match(r.body.secret, /^[A-Z2-7]{32}$/);
    assert.ok(r.body.otpauthUrl.startsWith('otpauth://totp/'));
    assert.notEqual(c.user.totpPendingSecret, r.body.secret);
    assert.equal(TotpService.decrypt(c.user.totpPendingSecret), r.body.secret);
    assert.equal(c.user.totpEnabled, false, 'not on until a code is confirmed');
  });

  it('switches on only after a correct first code, then returns 8 one-time recovery codes', async () => {
    const c = await addUser({ role: 'admin' });
    const { body: { secret } } = await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } });
    const bad = await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: invalidFor(secret) } });
    assert.equal(bad.status, 400);
    assert.equal(c.user.totpEnabled, false);
    assert.equal((await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: {} })).status, 400);

    const ok = await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: TotpService.codeAt(secret) } });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.recoveryCodes.length, 8);
    assert.equal(c.user.totpEnabled, true);
    assert.equal(c.user.recoveryHashes.length, 8);
    assert.ok(!c.user.recoveryHashes.some(h => ok.body.recoveryCodes.map(x => x.replace('-', '')).includes(h)), 'only hashes are stored');
  });

  it('cannot be started again while it is on (409)', async () => {
    const c = await enrolled();
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } })).status, 409);
  });

  it('cannot be enabled without starting setup first', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: '123456' } })).status, 400);
  });
});

describe('the two-step login', () => {
  it('gives no session after the password alone, only a challenge', async () => {
    const c = await enrolled();
    const r = await login(c.phone, c.password);
    assert.equal(r.status, 200);
    assert.equal(r.body.requires2FA, true);
    assert.ok(r.body.challengeToken);
    assert.ok(!r.body.token);
  });

  it('a wrong password never produces a challenge', async () => {
    const c = await enrolled();
    const r = await login(c.phone, 'Wrong@1234');
    assert.equal(r.status, 401);
    assert.ok(!r.body.challengeToken);
  });

  it('a correct code completes the sign-in and the session works', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const r = await verify(challengeToken, TotpService.codeAt(c.secret));
    assert.equal(r.status, 200);
    assert.equal(r.body.user.twoFactorEnabled, true);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: r.body.token })).status, 200);
  });

  it('a wrong code is refused, and a code cannot be used twice (replay)', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 401);
    assert.equal((await verify(challengeToken, code)).status, 200);
    assert.equal((await verify(challengeToken, code)).status, 401, 'same code again');
  });

  it('accepts a code typed with a space', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify(challengeToken, code.slice(0, 3) + ' ' + code.slice(3))).status, 200);
  });

  it('the challenge cannot be used as a session, and a session cannot be used as a challenge', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: challengeToken })).status, 401);
    assert.equal((await verify(c.token, TotpService.codeAt(c.secret))).status, 401);
  });

  it('rejects garbage, expired and wrong-purpose challenges', async () => {
    const c = await enrolled();
    const secret = process.env.JWT_SECRET + ':2fa-challenge';
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify('garbage', code)).status, 401);
    const expired = jwt.sign({ id: c.user._id, purpose: '2fa', iat: Math.floor(Date.now() / 1000) - 3600 }, secret, { expiresIn: '5m' });
    assert.equal((await verify(expired, code)).status, 401);
    const wrongPurpose = jwt.sign({ id: c.user._id, purpose: 'other' }, secret, { expiresIn: '5m' });
    assert.equal((await verify(wrongPurpose, code)).status, 401);
  });

  it('rejects missing and non-string input with 400', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    assert.equal((await app.api('POST', `${base}/verify-2fa`, { body: { challengeToken } })).status, 400);
    assert.equal((await app.api('POST', `${base}/verify-2fa`, { body: { code: '123456' } })).status, 400);
    assert.equal((await verify(challengeToken, ['123456'])).status, 400);
    assert.equal((await verify(challengeToken, 'x'.repeat(100))).status, 400);
  });

  it('refuses a challenge for an account deactivated in the meantime', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    c.user.active = false;
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 401);
  });

  it('works the same for admins', async () => {
    const a = await enrolled('admin');
    assert.equal((await login(a.phone, a.password)).body.requires2FA, true);
  });
});

describe('the member login cannot be used to skip 2FA', () => {
  it('refuses a coordinator or admin who has 2FA on', async () => {
    for (const role of ['coordinator', 'admin']) {
      const acct = await enrolled(role);
      const r = await app.api('POST', '/api/auth/login', { body: { phoneNumber: acct.phone, password: acct.password } });
      assert.equal(r.status, 401);
      assert.ok(!r.body.token);
    }
  });
});

describe('recovery codes', () => {
  it('sign you in once each, in any letter case', async () => {
    const c = await enrolled();
    const use = async code => verify((await login(c.phone, c.password)).body.challengeToken, code);
    assert.equal((await use(c.recoveryCodes[0])).status, 200);
    assert.equal((await use(c.recoveryCodes[0])).status, 401, 'second use refused');
    assert.equal((await use(c.recoveryCodes[1].toUpperCase())).status, 200);
    assert.equal(c.user.recoveryHashes.length, 6);
  });
});

describe('brute-force protection', () => {
  it('locks the account after 5 wrong codes, even for the right code, until the lock expires', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    for (let i = 0; i < 4; i++) assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 401);
    assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 429, 'fifth wrong code locks');
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 429, 'right code refused while locked');
    c.user.totpLockedUntil = new Date(Date.now() - 1000);
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 200, 'works once the lock ends');
  });
});

describe('turning 2FA off', () => {
  it('needs the password and a valid code', async () => {
    const c = await enrolled();
    const off = body => app.api('POST', `${base}/2fa/disable`, { token: c.token, body });
    assert.equal((await off({ password: 'Wrong@1234', code: TotpService.codeAt(c.secret) })).status, 400);
    assert.equal((await off({ password: c.password, code: invalidFor(c.secret) })).status, 400);
    assert.equal((await off({ password: c.password })).status, 400);
    assert.equal(c.user.totpEnabled, true, 'still on after every failed attempt');
    assert.equal((await off({ password: c.password, code: TotpService.codeAt(c.secret) })).status, 200);
    assert.equal(c.user.totpEnabled, false);
    assert.equal(c.user.totpSecret, null);
    assert.equal(c.user.recoveryHashes.length, 0);
  });

  it('returns sign-in to a single step', async () => {
    const c = await enrolled();
    await app.api('POST', `${base}/2fa/disable`, { token: c.token, body: { password: c.password, code: c.recoveryCodes[0] } });
    const r = await login(c.phone, c.password);
    assert.ok(r.body.token);
    assert.ok(!r.body.requires2FA);
  });

  it('refuses when 2FA is not on', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/disable`, { token: c.token, body: { password: c.password, code: '123456' } })).status, 400);
  });
});

describe('admin reset of a lost authenticator', () => {
  it('switches 2FA off for that account and signs them out', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    const stale = oldToken(c.user, 120);
    const r = await app.api('POST', `/api/admin/users/${c.user._id}/reset-2fa`, { token: admin.token });
    assert.equal(r.status, 200);
    assert.equal(c.user.totpEnabled, false);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: stale })).status, 401);
    assert.ok((await login(c.phone, c.password)).body.token, 'can sign in with just the password again');
  });

  it('is admin-only, cannot target yourself, and validates the id', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    assert.equal((await app.api('POST', `/api/admin/users/${c.user._id}/reset-2fa`, { token: c.token })).status, 403);
    assert.equal((await app.api('POST', `/api/admin/users/${admin.user._id}/reset-2fa`, { token: admin.token })).status, 400);
    assert.equal((await app.api('POST', '/api/admin/users/nope/reset-2fa', { token: admin.token })).status, 400);
    assert.equal((await app.api('POST', `/api/admin/users/${'e'.repeat(24)}/reset-2fa`, { token: admin.token })).status, 404);
  });
});

describe('what the API never reveals', () => {
  it('login, verify and list responses contain no secrets', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const v = await verify(challengeToken, TotpService.codeAt(c.secret));
    const list = await app.api('GET', '/api/admin/users', { token: admin.token });
    const text = JSON.stringify([v.body.user, list.body]);
    for (const leak of ['passwordHash', 'totpSecret', 'totpPendingSecret', 'recoveryHashes', c.secret]) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/twofactor.api.test.js"
cat > tests/errors.api.test.js << '__SAFEREACH_EOF__'
// Robustness: bad input and internal failures must produce clean errors and
// never take the server down.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
const realConsoleError = console.error;
// The server logs unexpected errors (that is the point of these tests), so keep
// that expected noise out of the test report.
before(async () => { console.error = () => {}; app = await startApp(); });
after(async () => { console.error = realConsoleError; await app.close(); });
beforeEach(() => fakes.reset());

describe('basics', () => {
  it('GET /api/health reports ok', async () => {
    const r = await app.api('GET', '/api/health');
    assert.equal(r.status, 200);
    assert.equal(r.body.status, 'ok');
    assert.ok(!Number.isNaN(Date.parse(r.body.time)));
  });

  it('unknown routes get a JSON 404', async () => {
    const r = await app.api('GET', '/api/nope');
    assert.equal(r.status, 404);
    assert.ok(r.body.error);
  });
});

describe('bad requests', () => {
  it('malformed JSON is a 400, not a 500', async () => {
    const r = await app.api('POST', '/api/auth/login', { raw: '{"phoneNumber": ' });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /json/i);
  });

  it('an oversized body is a 413', async () => {
    const r = await app.api('POST', '/api/auth/login', { raw: JSON.stringify({ x: 'a'.repeat(200 * 1024) }) });
    assert.equal(r.status, 413);
  });

  it('non-object JSON bodies are rejected cleanly', async () => {
    for (const raw of ['[]', 'null', '"text"', '123']) {
      for (const p of ['/api/auth/login', '/api/auth/register', '/api/coordinator/auth/login']) {
        const r = await app.api('POST', p, { raw });
        assert.equal(r.status, 400, `${p} <- ${raw}`);
      }
    }
  });

  it('empty bodies are rejected cleanly on every public POST', async () => {
    for (const p of ['/api/auth/login', '/api/auth/register', '/api/coordinator/auth/login', '/api/coordinator/auth/verify-2fa']) {
      assert.equal((await app.api('POST', p, { body: {} })).status, 400, p);
    }
  });
});

describe('internal failures', () => {
  it('an unexpected error becomes a generic 500 with no stack trace or internals', async () => {
    const { phone, password } = await addUser();
    state.failNext.add('UserRepository.findByPhone');
    const r = await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } });
    assert.equal(r.status, 500);
    const text = JSON.stringify(r.body);
    assert.ok(!text.includes('simulated'), 'internal message leaked');
    assert.ok(!/stack|\.js:\d+/i.test(text), 'stack trace leaked');
  });

  it('the server keeps serving after an internal error (async handlers cannot crash it)', async () => {
    const { phone, password } = await addUser();
    state.failNext.add('UserRepository.findByPhone');
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } })).status, 500);
    assert.equal((await app.api('GET', '/api/health')).status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } })).status, 200);
  });

  it('a failure inside an admin route is also contained', async () => {
    const admin = await addUser({ role: 'admin' });
    state.failNext.add('UserRepository.create');
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { fullName: 'New Person', phoneNumber: '+27820009999', password: 'Coord@1234', role: 'coordinator' } });
    assert.equal(r.status, 500);
    assert.equal((await app.api('GET', '/api/admin/users', { token: admin.token })).status, 200);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/errors.api.test.js"
cat > tests/models.test.js << '__SAFEREACH_EOF__'
// Mongoose model checks that need no database connection: schema rules and
// that secrets can never be serialised. Skipped automatically if mongoose is
// not installed.
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

let mongoose = null;
try { mongoose = require('mongoose'); } catch (e) { /* not installed */ }

describe('User model', { skip: mongoose ? false : 'mongoose is not installed' }, () => {
  const User = mongoose ? require('../models/User') : null;
  const valid = { fullName: 'Jane Doe', phoneNumber: '+27821230001', passwordHash: 'hash' };

  it('applies sensible defaults', () => {
    const u = new User(valid);
    assert.equal(u.role, 'member');
    assert.equal(u.active, true);
    assert.equal(u.totpEnabled, false);
    assert.equal(u.ngoBranch, null);
    assert.equal(u.validateSync(), undefined);
  });

  it('requires the core fields and a known role', () => {
    assert.ok(new User({ ...valid, passwordHash: undefined }).validateSync());
    assert.ok(new User({ ...valid, phoneNumber: undefined }).validateSync());
    assert.ok(new User({ ...valid, role: 'superuser' }).validateSync());
  });

  it('hides the 2FA secrets from normal queries (select: false)', () => {
    for (const field of ['totpSecret', 'totpPendingSecret', 'recoveryHashes']) {
      assert.equal(User.schema.path(field).options.select, false, field);
    }
  });

  it('toSafeJSON never includes the password hash or any 2FA secret', () => {
    const u = new User({ ...valid, role: 'coordinator', totpEnabled: true, totpSecret: 'SECRET', recoveryHashes: ['recovery-hash-value-xyz'] });
    const safe = u.toSafeJSON();
    const text = JSON.stringify(safe);
    for (const leak of ['passwordHash', 'hash', 'totpSecret', 'SECRET', 'recoveryHashes', 'recovery-hash-value-xyz']) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
    assert.equal(safe.role, 'coordinator');
    assert.equal(safe.twoFactorEnabled, true);
    assert.equal(safe.active, true);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/models.test.js"
cat > .circleci/config.yml << '__SAFEREACH_EOF__'
version: 2.1
jobs:
  build-and-test:
    docker:
      - image: cimg/node:20.18
    steps:
      - checkout
      - run:
          name: Install dependencies
          command: npm install
      - run:
          name: Run automated tests
          command: npm test
workflows:
  backend-ci:
    jobs:
      - build-and-test:
          filters:
            branches:
              only: main
__SAFEREACH_EOF__
echo "  wrote .circleci/config.yml"
node -e "
const fs = require('fs');
const p = JSON.parse(fs.readFileSync('package.json', 'utf8'));
p.scripts = p.scripts || {};
p.scripts.test = 'node --test tests/*.test.js';
fs.writeFileSync('package.json', JSON.stringify(p, null, 2) + '\\n');
console.log('  updated package.json (npm test)');
"
for f in server.js services/AuthService.js services/TotpService.js tests/*.js tests/helpers/*.js; do node --check "$f" || { echo "SYNTAX ERROR in $f"; exit 1; }; done
echo
echo "Done. Now run:  npm test"
