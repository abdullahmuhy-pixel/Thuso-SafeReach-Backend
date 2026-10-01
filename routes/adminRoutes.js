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
