#!/bin/sh
# apply-2fa.sh — installs the two-factor-authentication backend files into the right folders.
# Run from the repo root:  sh apply-2fa.sh
set -e
[ -f server.js ] && [ -d routes ] || { echo "Run this from the repo root (the folder containing server.js)."; exit 1; }
mkdir -p services models repositories routes
cat > services/AuthService.js << '__SAFEREACH_EOF__'
// services/AuthService.js
// Singleton pattern (Task 1, Section 4.3). All JWT issuing and verification
// goes through this one instance rather than being reimplemented in each
// route file. With medical data in the system, we wanted exactly one place
// that decides "is this user allowed to see this" — not three slightly
// different versions of that check scattered around the codebase.
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;

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
cat > services/TwoFactorService.js << '__SAFEREACH_EOF__'
// services/TwoFactorService.js — verifies a 2FA code (authenticator code or
// one-time recovery code) with replay protection and a lockout after repeated
// failures, so the 6-digit code cannot be brute-forced.
const TotpService = require('./TotpService');
const UserRepository = require('../repositories/UserRepository');

const FAIL_LIMIT = 5;
const LOCK_MS = 15 * 60 * 1000;

// `user` must be loaded with the 2FA fields (UserRepository.findByIdWith2FA).
async function verifyForUser(user, rawInput, now = Date.now()) {
  if (user.totpLockedUntil && new Date(user.totpLockedUntil).getTime() > now) {
    return { ok: false, reason: 'locked' };
  }

  const input = typeof rawInput === 'string' ? rawInput.replace(/[\s-]/g, '') : '';
  let ok = false;

  if (/^\d{6}$/.test(input)) {
    const step = TotpService.matchStep(TotpService.decrypt(user.totpSecret), input, now);
    // claimTotpStep is atomic: a code can only be used once, even if two
    // requests arrive at the same moment.
    ok = step !== null && await UserRepository.claimTotpStep(user._id, step);
  } else if (/^[a-f0-9]{10}$/i.test(input)) {
    ok = await UserRepository.consumeRecoveryHash(user._id, TotpService.hashRecovery(input));
  }

  if (ok) {
    await UserRepository.resetTotpFailures(user._id);
    return { ok: true };
  }
  const locked = await UserRepository.recordTotpFailure(user._id, FAIL_LIMIT, LOCK_MS);
  return { ok: false, reason: locked ? 'locked' : 'invalid' };
}

module.exports = { verifyForUser, FAIL_LIMIT, LOCK_MS };
__SAFEREACH_EOF__
echo "  wrote services/TwoFactorService.js"
cat > models/User.js << '__SAFEREACH_EOF__'
// models/User.js — matches USER entity in the Task 1 ER diagram (Section 3.4)
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  phoneNumber: { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  role: {
    type: String,
    enum: ['member', 'coordinator', 'admin'],
    default: 'member',
    required: true,
  },
  // Only populated for role === 'coordinator'
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
  // Soft-delete flag: deactivated accounts cannot sign in, but their check-ins,
  // alerts and reports stay in the database for the audit trail.
  // (Accounts created before this field existed are treated as active.)
  active: { type: Boolean, default: true },
  // Tokens issued before this moment are rejected (see middleware/auth.js)
  passwordChangedAt: { type: Date, default: null },

  // ── Two-factor authentication (coordinators and admins only) ───────────
  totpEnabled: { type: Boolean, default: false },
  // These three are never returned by normal queries (select: false) — code
  // that needs them asks for them explicitly (UserRepository.findByIdWith2FA).
  totpSecret: { type: String, default: null, select: false },          // AES-GCM encrypted
  totpPendingSecret: { type: String, default: null, select: false },   // during setup, before the first code is confirmed
  recoveryHashes: { type: [String], default: [], select: false },      // SHA-256 of unused recovery codes
  totpLastStep: { type: Number, default: null },                       // replay protection
  totpFailures: { type: Number, default: 0 },
  totpLockedUntil: { type: Date, default: null },
}, { timestamps: { createdAt: 'createdAt', updatedAt: false } });

// Never serialise the password hash or 2FA secrets back to the client
userSchema.methods.toSafeJSON = function () {
  const { _id, fullName, phoneNumber, role, createdAt, ngoBranch } = this;
  return {
    id: _id, fullName, phoneNumber, role, createdAt,
    ngoBranch: ngoBranch || null,
    active: this.active !== false,
    twoFactorEnabled: this.totpEnabled === true,
  };
};

module.exports = mongoose.model('User', userSchema);
__SAFEREACH_EOF__
echo "  wrote models/User.js"
cat > repositories/UserRepository.js << '__SAFEREACH_EOF__'
// repositories/UserRepository.js
// Repository pattern (Task 1, Section 4.4): route handlers never touch
// Mongoose/User directly — they go through here. This keeps the API layer
// testable without a live database connection, and means the database
// implementation can change without touching route logic.
const User = require('../models/User');

const WITH_2FA = '+totpSecret +totpPendingSecret +recoveryHashes';

class UserRepository {
  async create(userData) {
    return User.create(userData);
  }

  async findByPhone(phoneNumber) {
    return User.findOne({ phoneNumber });
  }

  async findById(id) {
    return User.findById(id);
  }

  // Same as findById but also loads the hidden 2FA secret fields.
  async findByIdWith2FA(id) {
    return User.findById(id).select(WITH_2FA);
  }

  async findCoordinatorsByBranch(branchId) {
    return User.find({ role: 'coordinator', ngoBranch: branchId });
  }

  async updateRole(id, role) {
    return User.findByIdAndUpdate(id, { role }, { new: true });
  }

  // Soft delete / restore — records stay, sign-in stops.
  async setActive(id, active) {
    return User.findByIdAndUpdate(id, { active }, { new: true });
  }

  async setBranch(id, branchId) {
    return User.findByIdAndUpdate(id, { ngoBranch: branchId }, { new: true });
  }

  // Also stamps passwordChangedAt so older sessions stop working.
  async updatePassword(id, passwordHash) {
    return User.findByIdAndUpdate(
      id,
      { passwordHash, passwordChangedAt: new Date() },
      { new: true }
    );
  }

  async list({ role } = {}) {
    const filter = role ? { role } : {};
    return User.find(filter)
      .select('-passwordHash')
      .populate('ngoBranch', 'branchName region')
      .sort({ createdAt: -1 });
  }

  // ── 2FA ───────────────────────────────────────────────────────────────
  async setPendingSecret(id, encryptedSecret) {
    return User.findByIdAndUpdate(id, { totpPendingSecret: encryptedSecret }, { new: true });
  }

  async enableTotp(id, encryptedSecret, recoveryHashes, step) {
    return User.findByIdAndUpdate(id, {
      totpEnabled: true,
      totpSecret: encryptedSecret,
      totpPendingSecret: null,
      recoveryHashes,
      totpLastStep: step,
      totpFailures: 0,
      totpLockedUntil: null,
    }, { new: true });
  }

  // revokeSessions: also invalidate every existing session (used by admin reset).
  async disableTotp(id, { revokeSessions = false } = {}) {
    const update = {
      totpEnabled: false,
      totpSecret: null,
      totpPendingSecret: null,
      recoveryHashes: [],
      totpLastStep: null,
      totpFailures: 0,
      totpLockedUntil: null,
    };
    if (revokeSessions) update.passwordChangedAt = new Date();
    return User.findByIdAndUpdate(id, update, { new: true });
  }

  // Atomic "use this 30-second step once": true only for the first caller.
  async claimTotpStep(id, step) {
    const r = await User.updateOne(
      { _id: id, $or: [{ totpLastStep: null }, { totpLastStep: { $lt: step } }] },
      { totpLastStep: step }
    );
    return r.modifiedCount === 1;
  }

  // Atomic: removes the hash and reports whether it was still unused.
  async consumeRecoveryHash(id, hash) {
    const r = await User.updateOne({ _id: id, recoveryHashes: hash }, { $pull: { recoveryHashes: hash } });
    return r.modifiedCount === 1;
  }

  async resetTotpFailures(id) {
    return User.updateOne({ _id: id }, { totpFailures: 0, totpLockedUntil: null });
  }

  // Returns true if this failure triggered a lockout.
  async recordTotpFailure(id, limit, lockMs) {
    const u = await User.findByIdAndUpdate(id, { $inc: { totpFailures: 1 } }, { new: true });
    if (u && u.totpFailures >= limit) {
      await User.updateOne({ _id: id }, { totpFailures: 0, totpLockedUntil: new Date(Date.now() + lockMs) });
      return true;
    }
    return false;
  }
}

// Exported as a single shared instance — every route imports the same
// repository object, consistent with how the rest of the data layer works.
module.exports = new UserRepository();
__SAFEREACH_EOF__
echo "  wrote repositories/UserRepository.js"
cat > routes/authRoutes.js << '__SAFEREACH_EOF__'
// routes/authRoutes.js — Member-facing registration & login, plus password
// change for any signed-in user (members, coordinators and admins).
// Members are ordinary community beneficiaries, so unlike the coordinator
// side (which is pre-provisioned, see seed/seedCoordinators.js) members
// CAN self-register here. Passwords are hashed with bcrypt at 12 salt
// rounds (Task 1 non-functional requirement: encrypted, access-controlled
// personal data).
const express = require('express');
const rateLimit = require('express-rate-limit');
const UserRepository = require('../repositories/UserRepository');
const AuthService = require('../services/AuthService');
const { authenticate } = require('../middleware/auth');
const { validateBody, isValid } = require('../middleware/validators');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts — please try again later' },
});

// Tighter than the global limit: a stolen token must not be usable to guess
// the current password.
const passwordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many password change attempts — please try again later' },
});

router.post(
  '/register',
  validateBody(
    { fullName: 'fullName', phoneNumber: 'phoneNumber', password: 'password' },
    ['fullName', 'phoneNumber', 'password']
  ),
  async (req, res) => {
    const { fullName, phoneNumber, password } = req.body;

    const existing = await UserRepository.findByPhone(phoneNumber);
    if (existing) return res.status(409).json({ error: 'An account with this number already exists' });

    const passwordHash = await AuthService.hashPassword(password);
    const user = await UserRepository.create({
      fullName,
      phoneNumber,
      passwordHash,
      role: 'member',
    });

    const token = AuthService.issueToken(user);
    return res.status(201).json({ token, user: user.toSafeJSON() });
  }
);

router.post('/login', loginLimiter, async (req, res) => {
  const { phoneNumber, password } = req.body;

  if (!isValid('phoneNumber', phoneNumber) || typeof password !== 'string' || !password || password.length > 200) {
    return res.status(400).json({ error: 'Invalid phone number or password' });
  }

  const user = await UserRepository.findByPhone(phoneNumber);
  // Members only. Coordinators and admins must use /api/coordinator/auth/login,
  // which is where two-factor authentication is enforced — letting them in here
  // would bypass it.
  if (!user || user.role !== 'member') return res.status(401).json({ error: 'Authentication failed' });

  const match = await AuthService.verifyPassword(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Authentication failed' });

  // Only revealed once the password was right, so it cannot be used to
  // discover which phone numbers have accounts.
  if (user.active === false) {
    return res.status(403).json({ error: 'This account has been deactivated. Contact your administrator.' });
  }

  const token = AuthService.issueToken(user);
  return res.json({ token, user: user.toSafeJSON() });
});

// Change your own password. Needs the current password; on success every
// older session is revoked and a fresh token is returned for this one.
// (A wrong current password is a 400, not 401, so clients don't treat it as
// an expired session and sign the user out.)
router.patch(
  '/password',
  passwordLimiter,
  authenticate,
  validateBody({ newPassword: 'password' }, ['currentPassword', 'newPassword']),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (typeof currentPassword !== 'string' || currentPassword.length > 200) {
      return res.status(400).json({ error: 'Invalid current password' });
    }
    const match = await AuthService.verifyPassword(currentPassword, req.user.passwordHash);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect' });

    if (currentPassword === newPassword) {
      return res.status(400).json({ error: 'New password must be different from the current one' });
    }

    const passwordHash = await AuthService.hashPassword(newPassword);
    const updated = await UserRepository.updatePassword(req.user._id, passwordHash);
    const token = AuthService.issueToken(updated);
    return res.json({ success: true, token });
  }
);

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/authRoutes.js"
cat > routes/coordinatorAuthRoutes.js << '__SAFEREACH_EOF__'
// routes/coordinatorAuthRoutes.js — Coordinator & Admin login only, with
// optional two-factor authentication (authenticator app codes, RFC 6238).
// There is deliberately NO /api/coordinator/register endpoint. Coordinator
// and admin accounts are created by an existing admin (see routes/adminRoutes.js
// manageUsers endpoint) or by the one-time seed script in seed/seedCoordinators.js.
// This mirrors the static-login pattern the group already used on the
// APDS7311 employee portal, adapted here for the coordinator/admin roles.
//
// Login with 2FA switched on is two steps:
//   1. POST /login       password OK  ->  { requires2FA: true, challengeToken }
//   2. POST /verify-2fa  challengeToken + code  ->  { token, user }
const express = require('express');
const rateLimit = require('express-rate-limit');
const UserRepository = require('../repositories/UserRepository');
const AuthService = require('../services/AuthService');
const TotpService = require('../services/TotpService');
const { verifyForUser } = require('../services/TwoFactorService');
const { authenticate, requireRole } = require('../middleware/auth');
const { isValid, validateBody } = require('../middleware/validators');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts — please try again later' },
});

const twoFactorLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many two-factor attempts — please try again later' },
});

const ELIGIBLE = ['coordinator', 'admin'];

router.post('/login', loginLimiter, async (req, res) => {
  const { phoneNumber, password } = req.body;

  if (!isValid('phoneNumber', phoneNumber) || typeof password !== 'string' || !password || password.length > 200) {
    return res.status(400).json({ error: 'Invalid phone number or password' });
  }

  const user = await UserRepository.findByPhone(phoneNumber);
  if (!user || !ELIGIBLE.includes(user.role)) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  const match = await AuthService.verifyPassword(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Authentication failed' });

  if (user.active === false) {
    return res.status(403).json({ error: 'This account has been deactivated. Contact an administrator.' });
  }

  // Password was right. If 2FA is on, no session yet — hand back a short-lived
  // challenge that only works at /verify-2fa.
  if (user.totpEnabled === true) {
    return res.json({ requires2FA: true, challengeToken: AuthService.issueChallengeToken(user) });
  }

  const token = AuthService.issueToken(user);
  return res.json({ token, user: user.toSafeJSON() });
});

router.post('/verify-2fa', twoFactorLimiter, validateBody({}, ['challengeToken', 'code']), async (req, res) => {
  const { challengeToken, code } = req.body;
  if (typeof challengeToken !== 'string' || typeof code !== 'string' || code.length > 40) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  let decoded;
  try {
    decoded = AuthService.verifyChallengeToken(challengeToken);
  } catch (err) {
    return res.status(401).json({ error: 'Sign-in expired — please enter your password again' });
  }

  const user = await UserRepository.findByIdWith2FA(decoded.id);
  if (!user || !ELIGIBLE.includes(user.role) || user.active === false || user.totpEnabled !== true) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  const result = await verifyForUser(user, code);
  if (!result.ok) {
    return result.reason === 'locked'
      ? res.status(429).json({ error: 'Too many wrong codes — try again in 15 minutes' })
      : res.status(401).json({ error: 'Incorrect code' });
  }

  const token = AuthService.issueToken(user);
  return res.json({ token, user: user.toSafeJSON() });
});

// ── Managing your own 2FA (needs a signed-in coordinator/admin session) ─────
// Wrong passwords/codes here are 400s, not 401s, so the dashboard doesn't
// mistake them for an expired session.
const guard = [twoFactorLimiter, authenticate, requireRole(...ELIGIBLE)];

// Step 1: re-enter your password, get a secret to add to your authenticator app.
router.post('/2fa/setup', ...guard, validateBody({}, ['password']), async (req, res) => {
  if (typeof req.body.password !== 'string' || req.body.password.length > 200) {
    return res.status(400).json({ error: 'Invalid password' });
  }
  if (!(await AuthService.verifyPassword(req.body.password, req.user.passwordHash))) {
    return res.status(400).json({ error: 'Password is incorrect' });
  }
  if (req.user.totpEnabled === true) {
    return res.status(409).json({ error: 'Two-factor authentication is already on' });
  }

  const secret = TotpService.generateSecret();
  await UserRepository.setPendingSecret(req.user._id, TotpService.encrypt(secret));
  return res.json({ secret, otpauthUrl: TotpService.otpauthUrl(secret, req.user.phoneNumber) });
});

// Step 2: prove the app is set up by entering the first code. Returns the
// one-time recovery codes — shown once, only their hashes are stored.
router.post('/2fa/enable', ...guard, validateBody({}, ['code']), async (req, res) => {
  const { code } = req.body;
  if (typeof code !== 'string') return res.status(400).json({ error: 'Invalid code' });

  const user = await UserRepository.findByIdWith2FA(req.user._id);
  if (user.totpEnabled === true) return res.status(409).json({ error: 'Two-factor authentication is already on' });
  if (!user.totpPendingSecret) return res.status(400).json({ error: 'Start setup first' });

  const step = TotpService.matchStep(TotpService.decrypt(user.totpPendingSecret), code.replace(/\s/g, ''));
  if (step === null) return res.status(400).json({ error: 'Incorrect code — check your authenticator app and try again' });

  const { plain, hashes } = TotpService.generateRecoveryCodes(8);
  await UserRepository.enableTotp(user._id, user.totpPendingSecret, hashes, step);
  return res.json({ success: true, recoveryCodes: plain });
});

// Turning it off needs BOTH your password and a current code (or recovery code).
router.post('/2fa/disable', ...guard, validateBody({}, ['password', 'code']), async (req, res) => {
  const { password, code } = req.body;
  if (typeof password !== 'string' || password.length > 200 || typeof code !== 'string' || code.length > 40) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  if (!(await AuthService.verifyPassword(password, req.user.passwordHash))) {
    return res.status(400).json({ error: 'Password is incorrect' });
  }
  const user = await UserRepository.findByIdWith2FA(req.user._id);
  if (user.totpEnabled !== true) return res.status(400).json({ error: 'Two-factor authentication is not on' });

  const result = await verifyForUser(user, code);
  if (!result.ok) {
    return result.reason === 'locked'
      ? res.status(429).json({ error: 'Too many wrong codes — try again in 15 minutes' })
      : res.status(400).json({ error: 'Incorrect code' });
  }
  await UserRepository.disableTotp(user._id);
  return res.json({ success: true });
});

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/coordinatorAuthRoutes.js"
cat > routes/adminRoutes.js << '__SAFEREACH_EOF__'
// routes/adminRoutes.js — "Manage Users & Roles" and "Configure Notification
// Channels" from the Task 1 use case diagram (Admin actor). This is also
// where new coordinator accounts get created day-to-day — the seed script
// (seed/seedCoordinators.js) only covers the very first coordinator so an
// admin account exists to create the rest through here.
const express = require('express');
const UserRepository = require('../repositories/UserRepository');
const BranchRepository = require('../repositories/BranchRepository');
const AuthService = require('../services/AuthService');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, validateParams, isValid } = require('../middleware/validators');

const router = express.Router();
router.use(authenticate, requireRole('admin'));

const ROLES = ['member', 'coordinator', 'admin'];
const sameId = (a, b) => String(a) === String(b);

// ── Users ───────────────────────────────────────────────────────────────
router.get('/users', async (req, res) => {
  const { role } = req.query;
  if (role !== undefined && !ROLES.includes(role)) {
    return res.status(400).json({ error: 'Invalid role filter' });
  }
  const users = await UserRepository.list({ role });
  return res.json(users);
});

// Admin-created coordinator/admin accounts — there is still no public
// /register endpoint for these roles (Task 1 static-login-style pattern).
router.post(
  '/users',
  validateBody(
    { fullName: 'fullName', phoneNumber: 'phoneNumber', password: 'password' },
    ['fullName', 'phoneNumber', 'password', 'role']
  ),
  async (req, res) => {
    const { fullName, phoneNumber, password, role, ngoBranch } = req.body;

    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });

    let branchId = null;
    if (role === 'coordinator' && ngoBranch) {
      if (!isValid('mongoId', ngoBranch)) return res.status(400).json({ error: 'Invalid branch' });
      const branch = await BranchRepository.findById(ngoBranch);
      if (!branch) return res.status(400).json({ error: 'Branch not found' });
      branchId = branch._id;
    }

    const existing = await UserRepository.findByPhone(phoneNumber);
    if (existing) return res.status(409).json({ error: 'An account with this number already exists' });

    const passwordHash = await AuthService.hashPassword(password);
    const user = await UserRepository.create({
      fullName, phoneNumber, passwordHash, role,
      ngoBranch: branchId,
    });

    return res.status(201).json({ success: true, user: user.toSafeJSON() });
  }
);

router.patch('/users/:id/role', validateParams({ id: 'mongoId' }), async (req, res) => {
  const { role } = req.body;
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });

  // The acting admin is always an active admin, so blocking self-changes is
  // enough to guarantee at least one admin always remains.
  if (sameId(req.params.id, req.user._id)) {
    return res.status(400).json({ error: 'You cannot change your own role' });
  }

  const target = await UserRepository.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  let user = await UserRepository.updateRole(req.params.id, role);
  // A branch only makes sense for coordinators.
  if (role !== 'coordinator' && target.ngoBranch) {
    user = await UserRepository.setBranch(req.params.id, null);
  }
  return res.json({ success: true, user: user.toSafeJSON() });
});

// Soft delete: deactivate keeps the account's check-ins, alerts and reports
// (audit trail) but blocks sign-in. Send { active: true } to restore it.
router.patch('/users/:id/active', validateParams({ id: 'mongoId' }), async (req, res) => {
  const { active } = req.body;
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: 'active must be true or false' });
  }
  if (sameId(req.params.id, req.user._id)) {
    return res.status(400).json({ error: 'You cannot deactivate your own account' });
  }
  const target = await UserRepository.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const user = await UserRepository.setActive(req.params.id, active);
  return res.json({ success: true, user: user.toSafeJSON() });
});

// Assign (or clear, with null) a coordinator's NGO branch.
router.patch('/users/:id/branch', validateParams({ id: 'mongoId' }), async (req, res) => {
  const { ngoBranch } = req.body;
  const target = await UserRepository.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role !== 'coordinator') {
    return res.status(400).json({ error: 'Only coordinators can belong to a branch' });
  }

  let branchId = null;
  if (ngoBranch !== null && ngoBranch !== undefined && ngoBranch !== '') {
    if (!isValid('mongoId', ngoBranch)) return res.status(400).json({ error: 'Invalid branch' });
    const branch = await BranchRepository.findById(ngoBranch);
    if (!branch) return res.status(400).json({ error: 'Branch not found' });
    branchId = branch._id;
  }
  const user = await UserRepository.setBranch(req.params.id, branchId);
  return res.json({ success: true, user: user.toSafeJSON() });
});

// Admin sets a temporary password for someone who forgot theirs. Their old
// sessions stop working. (Admins change their OWN password with
// PATCH /api/auth/password instead.)
router.post(
  '/users/:id/reset-password',
  validateParams({ id: 'mongoId' }),
  validateBody({ newPassword: 'password' }, ['newPassword']),
  async (req, res) => {
    if (sameId(req.params.id, req.user._id)) {
      return res.status(400).json({ error: 'Use "Change my password" for your own account' });
    }
    const target = await UserRepository.findById(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const passwordHash = await AuthService.hashPassword(req.body.newPassword);
    await UserRepository.updatePassword(req.params.id, passwordHash);
    return res.json({ success: true });
  }
);

// Lost phone? An admin switches 2FA off for that account (their sessions are
// signed out too) and they set it up again. Admins turn off their OWN 2FA from
// the Account screen, which needs their password and a code.
router.post('/users/:id/reset-2fa', validateParams({ id: 'mongoId' }), async (req, res) => {
  if (sameId(req.params.id, req.user._id)) {
    return res.status(400).json({ error: 'Use "Turn off" in your own Account screen' });
  }
  const target = await UserRepository.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  await UserRepository.disableTotp(req.params.id, { revokeSessions: true });
  return res.json({ success: true });
});

// ── NGO branches ────────────────────────────────────────────────────────
router.get('/branches', async (req, res) => {
  const branches = await BranchRepository.list();
  return res.json(branches);
});

router.post(
  '/branches',
  validateBody({ branchName: 'branchName', region: 'region' }, ['branchName', 'region']),
  async (req, res) => {
    const branchName = String(req.body.branchName).trim();
    const region = String(req.body.region).trim();
    const existing = await BranchRepository.findByName(branchName);
    if (existing) return res.status(409).json({ error: 'A branch with this name already exists' });
    const branch = await BranchRepository.create({ branchName, region });
    return res.status(201).json({ success: true, branch });
  }
);

// Placeholder for notification channel configuration (which channel is
// "preferred" per branch, quiet hours, etc.) — extends NotificationDispatcher
// once the group decides on real SMS/push providers in Task 2.
router.get('/notification-config', (req, res) => {
  return res.json({
    preferredChannel: 'push',
    fallbackChannel: 'sms',
    smsConfigured: Boolean(process.env.SMS_GATEWAY_API_KEY),
    pushConfigured: Boolean(process.env.PUSH_SERVICE_API_KEY),
  });
});

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/adminRoutes.js"
echo
for f in services/AuthService.js services/TotpService.js services/TwoFactorService.js models/User.js repositories/UserRepository.js routes/authRoutes.js routes/coordinatorAuthRoutes.js routes/adminRoutes.js; do node --check "$f" || { echo "SYNTAX ERROR in $f"; exit 1; }; done
echo "All files written and syntax-checked."
echo "Next: restart the server (npm run dev), then commit and sync."
