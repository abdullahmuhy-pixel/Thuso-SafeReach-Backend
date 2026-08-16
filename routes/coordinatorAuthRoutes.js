// routes/coordinatorAuthRoutes.js — Coordinator & Admin login only.
// There is deliberately NO /api/coordinator/register endpoint. Coordinator
// and admin accounts are created by an existing admin (see routes/adminRoutes.js
// manageUsers endpoint) or by the one-time seed script in seed/seedCoordinators.js.
// This mirrors the static-login pattern the group already used on the
// APDS7311 employee portal, adapted here for the coordinator/admin roles.
const express = require('express');
const rateLimit = require('express-rate-limit');
const UserRepository = require('../repositories/UserRepository');
const AuthService = require('../services/AuthService');
const { isValid } = require('../middleware/validators');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts — please try again later' },
});

router.post('/login', loginLimiter, async (req, res) => {
  const { phoneNumber, password } = req.body;

  if (!isValid('phoneNumber', phoneNumber) || !password) {
    return res.status(400).json({ error: 'Invalid phone number or password' });
  }

  const user = await UserRepository.findByPhone(phoneNumber);
  if (!user || !['coordinator', 'admin'].includes(user.role)) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  const match = await AuthService.verifyPassword(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Authentication failed' });

  const token = AuthService.issueToken(user);
  return res.json({ token, user: user.toSafeJSON() });
});

module.exports = router;
