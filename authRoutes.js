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
  if (!user) return res.status(401).json({ error: 'Authentication failed' });

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
