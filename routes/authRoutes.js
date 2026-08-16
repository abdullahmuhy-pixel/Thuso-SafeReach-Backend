// routes/authRoutes.js — Member-facing registration & login.
// Members are ordinary community beneficiaries, so unlike the coordinator
// side (which is pre-provisioned, see seed/seedCoordinators.js) members
// CAN self-register here. Passwords are hashed with bcrypt at 12 salt
// rounds (Task 1 non-functional requirement: encrypted, access-controlled
// personal data).
const express = require('express');
const rateLimit = require('express-rate-limit');
const UserRepository = require('../repositories/UserRepository');
const AuthService = require('../services/AuthService');
const { validateBody, isValid } = require('../middleware/validators');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts — please try again later' },
});

router.post(
  '/register',
  validateBody({ fullName: 'fullName', phoneNumber: 'phoneNumber', password: 'password' }),
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

  if (!isValid('phoneNumber', phoneNumber) || !password) {
    return res.status(400).json({ error: 'Invalid phone number or password' });
  }

  const user = await UserRepository.findByPhone(phoneNumber);
  if (!user) return res.status(401).json({ error: 'Authentication failed' });

  const match = await AuthService.verifyPassword(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Authentication failed' });

  const token = AuthService.issueToken(user);
  return res.json({ token, user: user.toSafeJSON() });
});

module.exports = router;
