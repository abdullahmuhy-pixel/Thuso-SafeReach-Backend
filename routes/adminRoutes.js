// routes/adminRoutes.js — "Manage Users & Roles" and "Configure Notification
// Channels" from the Task 1 use case diagram (Admin actor). This is also
// where new coordinator accounts get created day-to-day — the seed script
// (seed/seedCoordinators.js) only covers the very first coordinator so an
// admin account exists to create the rest through here.
const express = require('express');
const UserRepository = require('../repositories/UserRepository');
const AuthService = require('../services/AuthService');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, isValid } = require('../middleware/validators');

const router = express.Router();
router.use(authenticate, requireRole('admin'));

router.get('/users', async (req, res) => {
  const { role } = req.query;
  const users = await UserRepository.list({ role });
  return res.json(users);
});

// Admin-created coordinator/admin accounts — there is still no public
// /register endpoint for these roles (Task 1 static-login-style pattern).
router.post(
  '/users',
  validateBody({ fullName: 'fullName', phoneNumber: 'phoneNumber', password: 'password' }),
  async (req, res) => {
    const { fullName, phoneNumber, password, role, ngoBranch } = req.body;

    if (!['member', 'coordinator', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const existing = await UserRepository.findByPhone(phoneNumber);
    if (existing) return res.status(409).json({ error: 'An account with this number already exists' });

    const passwordHash = await AuthService.hashPassword(password);
    const user = await UserRepository.create({
      fullName, phoneNumber, passwordHash, role,
      ngoBranch: role === 'coordinator' ? ngoBranch || null : null,
    });

    return res.status(201).json({ success: true, user: user.toSafeJSON() });
  }
);

router.patch('/users/:id/role', async (req, res) => {
  const { role } = req.body;
  if (!['member', 'coordinator', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const user = await UserRepository.updateRole(req.params.id, role);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({ success: true, user: user.toSafeJSON() });
});

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
