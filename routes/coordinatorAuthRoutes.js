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
