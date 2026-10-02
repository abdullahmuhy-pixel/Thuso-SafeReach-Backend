#!/bin/sh
# apply-branches.sh — branch-scoped alerts, incident reports and member lists.
# Run from the repo root:  sh apply-branches.sh
set -e
[ -f server.js ] && [ -d routes ] || { echo "Run this from the repo root (the folder containing server.js)."; exit 1; }
[ -f tests/helpers/fakes.js ] || { echo "Install the test suite first (sh apply-tests.sh), then run this."; exit 1; }
mkdir -p models repositories services routes tests/helpers
cat > models/SOSAlert.js << '__SAFEREACH_EOF__'
// models/SOSAlert.js — matches SOS_ALERT entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const sosAlertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  checkInId: { type: mongoose.Schema.Types.ObjectId, ref: 'CheckIn', default: null },
  triggeredAt: { type: Date, required: true, default: Date.now },
  triggerSource: {
    type: String,
    enum: ['manual', 'shake', 'checkin_timeout'],
    default: 'manual',
  },
  lat: { type: Number, default: null },
  lng: { type: Number, default: null },
  status: {
    type: String,
    enum: ['active', 'resolved'],
    default: 'active',
  },
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedAt: { type: Date, default: null },
  // Branch of the member at the moment the alert was raised (null = member not
  // assigned to a branch). Stored on the alert so later reassignments don't
  // change who was responsible for it.
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
}, { timestamps: { createdAt: false, updatedAt: true } });

sosAlertSchema.index({ status: 1, triggeredAt: -1 });

module.exports = mongoose.model('SOSAlert', sosAlertSchema);
__SAFEREACH_EOF__
echo "  wrote models/SOSAlert.js"
cat > models/Incident.js << '__SAFEREACH_EOF__'
// models/Incident.js — matches INCIDENT entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: {
    type: String,
    enum: ['theft', 'assault', 'accident', 'fire', 'medical', 'checkin', 'other'],
    required: true,
  },
  description: { type: String, required: true, trim: true, maxlength: 1000 },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium',
  },
  location: { type: String, trim: true, default: '' },
  lat: { type: Number, default: null },
  lng: { type: Number, default: null },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  // Branch of the reporting member when the report was made (null = unassigned).
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
}, { timestamps: { createdAt: 'reportedAt', updatedAt: false } });

module.exports = mongoose.model('Incident', incidentSchema);
__SAFEREACH_EOF__
echo "  wrote models/Incident.js"
cat > repositories/SOSAlertRepository.js << '__SAFEREACH_EOF__'
// repositories/SOSAlertRepository.js
const SOSAlert = require('../models/SOSAlert');

// Branch filter for coordinators: their branch's alerts PLUS alerts from members
// not assigned to any branch. Unassigned alerts are visible to every coordinator
// so an SOS can never be lost just because nobody has set up branches yet.
const branchFilter = branchId => (branchId ? { $or: [{ ngoBranch: branchId }, { ngoBranch: null }] } : {});

class SOSAlertRepository {
  async create(data) {
    return SOSAlert.create(data);
  }

  async findById(id) {
    return SOSAlert.findById(id).populate('userId', 'fullName phoneNumber');
  }

  // branchId = null/undefined -> every branch (admins and unassigned coordinators)
  async findActive({ branchId } = {}) {
    return SOSAlert.find({ status: 'active', ...branchFilter(branchId) })
      .sort({ triggeredAt: 1 })
      .populate('userId', 'fullName phoneNumber');
  }

  async resolve(id, coordinatorId) {
    return SOSAlert.findByIdAndUpdate(
      id,
      { status: 'resolved', resolvedBy: coordinatorId, resolvedAt: new Date() },
      { new: true }
    );
  }
}

module.exports = new SOSAlertRepository();
__SAFEREACH_EOF__
echo "  wrote repositories/SOSAlertRepository.js"
cat > repositories/IncidentRepository.js << '__SAFEREACH_EOF__'
// repositories/IncidentRepository.js
const Incident = require('../models/Incident');

// Same rule as SOSAlertRepository: a coordinator sees their branch's reports plus
// reports from members who are not assigned to a branch.
const branchFilter = branchId => (branchId ? { $or: [{ ngoBranch: branchId }, { ngoBranch: null }] } : {});

class IncidentRepository {
  async create(data) {
    return Incident.create(data);
  }

  async findById(id) {
    return Incident.findById(id);
  }

  async findAll({ limit = 50, branchId } = {}) {
    return Incident.find(branchFilter(branchId))
      .sort({ reportedAt: -1 })
      .limit(limit)
      .populate('userId', 'fullName phoneNumber');
  }

  async findByUser(userId) {
    return Incident.find({ userId }).sort({ reportedAt: -1 });
  }

  async markReviewed(id, coordinatorId) {
    return Incident.findByIdAndUpdate(id, { reviewedBy: coordinatorId }, { new: true });
  }
}

module.exports = new IncidentRepository();
__SAFEREACH_EOF__
echo "  wrote repositories/IncidentRepository.js"
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

  // branchId set -> only that branch's users plus users with no branch
  // (used for the coordinator's member list).
  async list({ role, branchId } = {}) {
    const filter = role ? { role } : {};
    if (branchId) filter.$or = [{ ngoBranch: branchId }, { ngoBranch: null }];
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
cat > services/BranchScope.js << '__SAFEREACH_EOF__'
// services/BranchScope.js
// Who may see what. Alerts, incident reports and member records belong to the
// NGO branch of the member they concern.
//
//   * admins and coordinators with no branch  -> see everything
//   * coordinators with a branch              -> see their branch, plus anything
//                                                not assigned to a branch yet
//
// "Not assigned" items stay visible to every coordinator on purpose: an SOS must
// never go unseen because a member hasn't been placed in a branch.
function scopeFor(user) {
  if (!user || user.role === 'admin' || !user.ngoBranch) return { all: true, branchId: null };
  return { all: false, branchId: user.ngoBranch };
}

function canAccess(user, itemBranchId) {
  const scope = scopeFor(user);
  return scope.all || !itemBranchId || String(itemBranchId) === String(scope.branchId);
}

module.exports = { scopeFor, canAccess };
__SAFEREACH_EOF__
echo "  wrote services/BranchScope.js"
cat > services/CheckInSweeper.js << '__SAFEREACH_EOF__'
// services/CheckInSweeper.js
// The SafeReach frontend times its own check-in countdown client-side, but
// that only works while the app is open (see the note in the check-in
// overlay UI). This sweep runs server-side every 30 seconds and catches
// any check-in that expired while the member's app was closed or their
// phone was offline, so escalation doesn't depend on the client being alive.
const CheckInRepository = require('../repositories/CheckInRepository');
const SOSAlertRepository = require('../repositories/SOSAlertRepository');
const IncidentRepository = require('../repositories/IncidentRepository');
const UserRepository = require('../repositories/UserRepository');
const { dispatchAlert } = require('./NotificationDispatcher');

const SWEEP_INTERVAL_MS = 30 * 1000;
let sweepTimer = null;

async function sweepOnce() {
  const expired = await CheckInRepository.findAllExpiredActive();
  for (const checkIn of expired) {
    await CheckInRepository.markEscalated(checkIn._id);

    // Route the alert to the member's branch.
    const member = await UserRepository.findById(checkIn.userId);
    const ngoBranch = member ? member.ngoBranch || null : null;

    const alert = await SOSAlertRepository.create({
      userId: checkIn.userId,
      checkInId: checkIn._id,
      triggerSource: 'checkin_timeout',
      lat: checkIn.lat,
      lng: checkIn.lng,
      ngoBranch,
    });

    await IncidentRepository.create({
      userId: checkIn.userId,
      type: 'checkin',
      description: `Check-in "${checkIn.destination || 'trip'}" (${checkIn.durationMinutes} min) expired without confirmation.`,
      severity: 'high',
      location: checkIn.lat ? `${checkIn.lat}, ${checkIn.lng}` : 'Location not set',
      lat: checkIn.lat,
      lng: checkIn.lng,
      ngoBranch,
    });

    await dispatchAlert(alert);
    console.log(`[CheckInSweeper] Escalated check-in ${checkIn._id} -> alert ${alert._id}`);
  }
}

function start() {
  if (sweepTimer) return;
  sweepTimer = setInterval(() => {
    sweepOnce().catch(err => console.error('[CheckInSweeper] Sweep failed:', err.message));
  }, SWEEP_INTERVAL_MS);
  console.log('[CheckInSweeper] Started — checking for expired check-ins every 30s');
}

function stop() {
  if (sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = null;
  }
}

module.exports = { start, stop, sweepOnce };
__SAFEREACH_EOF__
echo "  wrote services/CheckInSweeper.js"
cat > routes/sosRoutes.js << '__SAFEREACH_EOF__'
// routes/sosRoutes.js — mirrors the SafeReach frontend SOS button and the
// new shake-to-SOS gesture (index.html: showSOS/onShakeDetected). Every
// trigger, whichever source it came from, ends up here and dispatches a
// notification via the Strategy pattern in services/NotificationDispatcher.js.
const express = require('express');
const SOSAlertRepository = require('../repositories/SOSAlertRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { isValid, validateParams } = require('../middleware/validators');
const { dispatchAlert } = require('../services/NotificationDispatcher');
const { scopeFor, canAccess } = require('../services/BranchScope');

const router = express.Router();

router.post('/', authenticate, requireRole('member'), async (req, res) => {
  const { checkInId, lat, lng, triggerSource } = req.body;

  if (lat !== undefined && !isValid('latLng', lat)) return res.status(400).json({ error: 'Invalid latitude' });
  if (lng !== undefined && !isValid('latLng', lng)) return res.status(400).json({ error: 'Invalid longitude' });
  if (checkInId !== undefined && checkInId !== null && !isValid('mongoId', checkInId)) {
    return res.status(400).json({ error: 'Invalid checkInId' });
  }

  const allowedSources = ['manual', 'shake', 'checkin_timeout'];
  const source = allowedSources.includes(triggerSource) ? triggerSource : 'manual';

  const alert = await SOSAlertRepository.create({
    userId: req.user._id,
    checkInId: checkInId || null,
    triggerSource: source,
    lat: lat ?? null,
    lng: lng ?? null,
    ngoBranch: req.user.ngoBranch || null, // routed to the member's branch
  });

  // Fire-and-forget from the caller's perspective — the member gets an
  // immediate 201, notification dispatch happens in the background.
  dispatchAlert(alert).catch(err => console.error('[sosRoutes] dispatch failed:', err.message));

  return res.status(201).json({ success: true, alertId: alert._id, status: alert.status });
});

// Coordinator-facing: view and resolve alerts
router.get('/', authenticate, requireRole('coordinator', 'admin'), async (req, res) => {
  const alerts = await SOSAlertRepository.findActive({ branchId: scopeFor(req.user).branchId });
  return res.json(alerts);
});

router.patch(
  '/:id/resolve',
  authenticate,
  requireRole('coordinator', 'admin'),
  validateParams({ id: 'mongoId' }),
  async (req, res) => {
    // Another branch's alert is reported as "not found" rather than "forbidden",
    // so a coordinator can't probe for alerts outside their scope.
    const existing = await SOSAlertRepository.findById(req.params.id);
    if (!existing || !canAccess(req.user, existing.ngoBranch)) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    const alert = await SOSAlertRepository.resolve(req.params.id, req.user._id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    return res.json({ success: true, alert });
  }
);

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/sosRoutes.js"
cat > routes/incidentRoutes.js << '__SAFEREACH_EOF__'
// routes/incidentRoutes.js — mirrors the SafeReach frontend "Report an
// Incident" feature (index.html: showReport/submitReport). The frontend
// currently only saves reports to localStorage; this endpoint is what lets
// Task 2 sync them to the cloud so a coordinator can actually see them,
// which is the whole point of building the coordinator layer.
const express = require('express');
const IncidentRepository = require('../repositories/IncidentRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, validateParams, isValid } = require('../middleware/validators');
const { scopeFor, canAccess } = require('../services/BranchScope');

const router = express.Router();

const INCIDENT_TYPES = ['theft', 'assault', 'accident', 'fire', 'medical', 'checkin', 'other'];

router.post(
  '/',
  authenticate,
  requireRole('member'),
  validateBody({ description: 'description', location: 'destination' }, ['type', 'description']),
  async (req, res) => {
    const { type, description, severity, location, lat, lng } = req.body;

    if (!INCIDENT_TYPES.includes(type)) {
      return res.status(400).json({ error: 'Invalid incident type' });
    }
    if (lat !== undefined && !isValid('latLng', lat)) return res.status(400).json({ error: 'Invalid latitude' });
    if (lng !== undefined && !isValid('latLng', lng)) return res.status(400).json({ error: 'Invalid longitude' });

    const incident = await IncidentRepository.create({
      userId: req.user._id,
      type,
      description,
      severity: ['low', 'medium', 'high'].includes(severity) ? severity : 'medium',
      location: location || '',
      lat: lat ?? null,
      lng: lng ?? null,
      ngoBranch: req.user.ngoBranch || null, // routed to the member's branch
    });

    return res.status(201).json({ success: true, incident });
  }
);

router.get('/mine', authenticate, requireRole('member'), async (req, res) => {
  const incidents = await IncidentRepository.findByUser(req.user._id);
  return res.json(incidents);
});

// Coordinator-facing
router.get('/', authenticate, requireRole('coordinator', 'admin'), async (req, res) => {
  const incidents = await IncidentRepository.findAll({ branchId: scopeFor(req.user).branchId });
  return res.json(incidents);
});

router.patch(
  '/:id/review',
  authenticate,
  requireRole('coordinator', 'admin'),
  validateParams({ id: 'mongoId' }),
  async (req, res) => {
    const existing = await IncidentRepository.findById(req.params.id);
    if (!existing || !canAccess(req.user, existing.ngoBranch)) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    const incident = await IncidentRepository.markReviewed(req.params.id, req.user._id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    return res.json({ success: true, incident });
  }
);

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/incidentRoutes.js"
cat > routes/coordinatorRoutes.js << '__SAFEREACH_EOF__'
// routes/coordinatorRoutes.js — the coordinator dashboard use cases from
// the Task 1 use case diagram (Section 3.1): "View Live Alerts", "Manage
// Member Records", "Generate Incident Reports".
//
// Everything here is scoped to the coordinator's NGO branch (see
// services/BranchScope.js): admins and coordinators without a branch see all
// branches; a branch coordinator sees their branch plus unassigned items.
const express = require('express');
const UserRepository = require('../repositories/UserRepository');
const SOSAlertRepository = require('../repositories/SOSAlertRepository');
const IncidentRepository = require('../repositories/IncidentRepository');
const BranchRepository = require('../repositories/BranchRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { scopeFor } = require('../services/BranchScope');

const router = express.Router();
router.use(authenticate, requireRole('coordinator', 'admin'));

// Single dashboard summary endpoint — active alerts + recent incidents in
// one call, so the coordinator UI doesn't need three separate round trips
// on load. `scope` tells the UI what the coordinator is looking at.
router.get('/dashboard', async (req, res) => {
  const scope = scopeFor(req.user);
  const [alerts, incidents, branch] = await Promise.all([
    SOSAlertRepository.findActive({ branchId: scope.branchId }),
    IncidentRepository.findAll({ limit: 20, branchId: scope.branchId }),
    scope.branchId ? BranchRepository.findById(scope.branchId) : null,
  ]);
  return res.json({
    activeAlerts: alerts,
    recentIncidents: incidents,
    scope: { all: scope.all, branch: branch ? { _id: branch._id, branchName: branch.branchName, region: branch.region } : null },
  });
});

router.get('/members', async (req, res) => {
  const members = await UserRepository.list({ role: 'member', branchId: scopeFor(req.user).branchId });
  return res.json(members);
});

module.exports = router;
__SAFEREACH_EOF__
echo "  wrote routes/coordinatorRoutes.js"
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
    if (role !== 'admin' && ngoBranch) {
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
  // Admins work across all branches, so they don't belong to one.
  if (role === 'admin' && target.ngoBranch) {
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

// Assign (or clear, with null) a member's or coordinator's NGO branch. A member's
// branch decides which coordinators see their alerts and reports.
router.patch('/users/:id/branch', validateParams({ id: 'mongoId' }), async (req, res) => {
  const { ngoBranch } = req.body;
  const target = await UserRepository.findById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') {
    return res.status(400).json({ error: 'Admins are not tied to a branch' });
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
  async list({ role, branchId } = {}) {
    return state.users
      .filter(u => (!role || u.role === role) && (!branchId || !u.ngoBranch || String(u.ngoBranch) === String(branchId)))
      .map(withoutSecrets);
  },
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
  async findActive({ branchId } = {}) {
    return state.alerts
      .filter(a => a.status === 'active' && (!branchId || !a.ngoBranch || String(a.ngoBranch) === String(branchId)))
      .map(a => ({ ...a, userId: populate(a.userId) }));
  },
  async resolve(id, by) {
    const a = state.alerts.find(x => x._id === String(id)); if (!a) return null;
    Object.assign(a, { status: 'resolved', resolvedBy: by, resolvedAt: new Date() }); return a;
  },
};

const IncidentRepository = {
  async create(d) { const i = { _id: oid(), reportedAt: new Date(), reviewedBy: null, ...d }; state.incidents.push(i); return i; },
  async findById(id) { return state.incidents.find(i => i._id === String(id)) || null; },
  async findAll({ limit = 50, branchId } = {}) {
    return state.incidents
      .filter(i => !branchId || !i.ngoBranch || String(i.ngoBranch) === String(branchId))
      .slice(-limit).reverse().map(i => ({ ...i, userId: populate(i.userId) }));
  },
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

  it('can place a new member in a branch', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'West', region: 'Gauteng' } });
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { fullName: 'New Member', phoneNumber: '+27820003333', password: 'Member@1234', role: 'member', ngoBranch: branch._id } });
    assert.equal(r.status, 201);
    assert.equal(r.body.user.ngoBranch, branch._id);
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

  it('clears the branch when someone becomes an admin (admins work across all branches), keeps it otherwise', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'North', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    c.user.ngoBranch = branch._id;
    await app.api('PATCH', `/api/admin/users/${c.user._id}/role`, { token: admin.token, body: { role: 'member' } });
    assert.equal(c.user.ngoBranch, branch._id, 'a demoted coordinator stays in their branch');
    await app.api('PATCH', `/api/admin/users/${c.user._id}/role`, { token: admin.token, body: { role: 'admin' } });
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

  it('assigns and clears a coordinator\'s or member\'s branch, but not an admin\'s', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'East', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    const m = await addUser();
    const other = await addUser({ role: 'admin' });
    const set = (id, ngoBranch) => app.api('PATCH', `/api/admin/users/${id}/branch`, { token: admin.token, body: { ngoBranch } });
    assert.equal((await set(c.user._id, branch._id)).status, 200);
    assert.equal(c.user.ngoBranch, branch._id);
    assert.equal((await set(c.user._id, null)).status, 200);
    assert.equal(c.user.ngoBranch, null);
    assert.equal((await set(m.user._id, branch._id)).status, 200, 'members can be placed in a branch');
    assert.equal(m.user.ngoBranch, branch._id);
    assert.equal((await set(other.user._id, branch._id)).status, 400, 'admins are not tied to a branch');
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
cat > tests/branches.api.test.js << '__SAFEREACH_EOF__'
// Branch-scoped visibility: a coordinator sees their own branch's alerts,
// incident reports and members — plus anything not yet assigned to a branch —
// while admins and branch-less coordinators see everything.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

// Two branches, a coordinator + member in each, plus an unassigned member,
// a branch-less coordinator and an admin.
async function world() {
  const admin = await addUser({ role: 'admin', name: 'Admin' });
  const mk = async (branchName, region) => (await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName, region } })).body.branch;
  const north = await mk('Thuso North', 'Gauteng');
  const south = await mk('Thuso South', 'Gauteng');
  const inBranch = async (user, branch) => { user.user.ngoBranch = branch._id; return user; };

  const w = {
    admin, north, south,
    coordN: await inBranch(await addUser({ role: 'coordinator', name: 'Coord North' }), north),
    coordS: await inBranch(await addUser({ role: 'coordinator', name: 'Coord South' }), south),
    coordAll: await addUser({ role: 'coordinator', name: 'Coord No Branch' }),
    memberN: await inBranch(await addUser({ name: 'Member North' }), north),
    memberS: await inBranch(await addUser({ name: 'Member South' }), south),
    memberNone: await addUser({ name: 'Member Unassigned' }),
  };
  return w;
}
const dash = (who) => app.api('GET', '/api/coordinator/dashboard', { token: who.token });
const names = list => list.map(a => a.userId.fullName).sort();

describe('alerts are routed to the member\'s branch', () => {
  it('stores the member\'s branch on the alert and on incident reports', async () => {
    const w = await world();
    const sos = await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    const rep = await app.api('POST', '/api/incidents', { token: w.memberN.token, body: { type: 'theft', description: 'Bag stolen' } });
    assert.equal(state.alerts.find(a => a._id === sos.body.alertId).ngoBranch, w.north._id);
    assert.equal(rep.body.incident.ngoBranch, w.north._id);
    const unassigned = await app.api('POST', '/api/sos', { token: w.memberNone.token, body: {} });
    assert.equal(state.alerts.find(a => a._id === unassigned.body.alertId).ngoBranch, null);
  });
});

describe('who sees which alerts', () => {
  it('branch coordinators see their branch + unassigned members, never another branch', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS, w.memberNone]) await app.api('POST', '/api/sos', { token: m.token, body: {} });

    assert.deepEqual(names((await dash(w.coordN)).body.activeAlerts), ['Member North', 'Member Unassigned']);
    assert.deepEqual(names((await dash(w.coordS)).body.activeAlerts), ['Member South', 'Member Unassigned']);
  });

  it('admins and coordinators without a branch see every alert', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS, w.memberNone]) await app.api('POST', '/api/sos', { token: m.token, body: {} });
    for (const who of [w.admin, w.coordAll]) {
      assert.equal((await dash(who)).body.activeAlerts.length, 3);
    }
  });

  it('the plain alerts list is scoped the same way', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS]) await app.api('POST', '/api/sos', { token: m.token, body: {} });
    const list = await app.api('GET', '/api/sos', { token: w.coordN.token });
    assert.equal(list.body.length, 1);
    assert.equal(list.body[0].userId.fullName, 'Member North');
  });

  it('tells the dashboard what the coordinator is looking at', async () => {
    const w = await world();
    const n = (await dash(w.coordN)).body.scope;
    assert.equal(n.all, false);
    assert.equal(n.branch.branchName, 'Thuso North');
    assert.equal((await dash(w.admin)).body.scope.all, true);
    assert.equal((await dash(w.coordAll)).body.scope.branch, null);
  });

  it('an alert keeps its branch even if the member is moved later', async () => {
    const w = await world();
    await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    await app.api('PATCH', `/api/admin/users/${w.memberN.user._id}/branch`, { token: w.admin.token, body: { ngoBranch: w.south._id } });
    assert.equal((await dash(w.coordN)).body.activeAlerts.length, 1, 'North still owns the alert it was sent');
    assert.equal((await dash(w.coordS)).body.activeAlerts.length, 0);
  });
});

describe('resolving and reviewing are scoped too', () => {
  it('a coordinator cannot resolve another branch\'s alert (404, nothing changes)', async () => {
    const w = await world();
    const { body: { alertId } } = await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    const r = await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: w.coordS.token });
    assert.equal(r.status, 404);
    assert.equal(state.alerts.find(a => a._id === alertId).status, 'active');
    assert.equal((await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: w.coordN.token })).status, 200);
  });

  it('anyone in scope can resolve unassigned alerts, and admins can resolve any', async () => {
    const w = await world();
    const a = (await app.api('POST', '/api/sos', { token: w.memberNone.token, body: {} })).body.alertId;
    const b = (await app.api('POST', '/api/sos', { token: w.memberS.token, body: {} })).body.alertId;
    assert.equal((await app.api('PATCH', `/api/sos/${a}/resolve`, { token: w.coordN.token })).status, 200);
    assert.equal((await app.api('PATCH', `/api/sos/${b}/resolve`, { token: w.admin.token })).status, 200);
  });

  it('incident reports: scoped list, and review is limited to your scope', async () => {
    const w = await world();
    const rN = (await app.api('POST', '/api/incidents', { token: w.memberN.token, body: { type: 'fire', description: 'North fire' } })).body.incident;
    await app.api('POST', '/api/incidents', { token: w.memberS.token, body: { type: 'fire', description: 'South fire' } });

    const mine = await dash(w.coordN);
    assert.deepEqual(mine.body.recentIncidents.map(i => i.description), ['North fire']);
    assert.equal((await app.api('GET', '/api/incidents', { token: w.coordS.token })).body.length, 1);
    assert.equal((await app.api('GET', '/api/incidents', { token: w.admin.token })).body.length, 2);

    assert.equal((await app.api('PATCH', `/api/incidents/${rN._id}/review`, { token: w.coordS.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/incidents/${rN._id}/review`, { token: w.coordN.token })).status, 200);
  });
});

describe('member records', () => {
  it('a branch coordinator sees their branch\'s members + unassigned ones only', async () => {
    const w = await world();
    const r = await app.api('GET', '/api/coordinator/members', { token: w.coordN.token });
    assert.deepEqual(r.body.map(m => m.fullName).sort(), ['Member North', 'Member Unassigned']);
    assert.equal((await app.api('GET', '/api/coordinator/members', { token: w.admin.token })).body.length, 3);
    assert.equal((await app.api('GET', '/api/coordinator/members', { token: w.coordAll.token })).body.length, 3);
  });
});

describe('missed check-ins are routed by branch as well', () => {
  const sweeper = require('../services/CheckInSweeper');
  const origLog = console.log;
  before(() => { console.log = () => {}; });
  after(() => { console.log = origLog; });

  it('the escalated alert and incident carry the member\'s branch', async () => {
    const w = await world();
    state.checkIns.push({ _id: 'c'.repeat(24), userId: w.memberS.user._id, status: 'active', durationMinutes: 5, destination: 'Soweto', lat: null, lng: null, expiresAt: new Date(Date.now() - 60000) });
    await sweeper.sweepOnce();
    assert.equal(state.alerts[0].ngoBranch, w.south._id);
    assert.equal(state.incidents[0].ngoBranch, w.south._id);
    assert.equal((await dash(w.coordS)).body.activeAlerts.length, 1);
    assert.equal((await dash(w.coordN)).body.activeAlerts.length, 0);
  });
});
__SAFEREACH_EOF__
echo "  wrote tests/branches.api.test.js"
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
| `branches.api.test.js` | Branch-scoped visibility: who sees which alerts, incident reports and members; routing by the member's branch |
| `admin.api.test.js` | Accounts, roles, branches, deactivate/reactivate, password reset |
| `twofactor.api.test.js` | Two-step login, recovery codes, replay and brute-force protection, resets |
| `errors.api.test.js` | Malformed input and internal failures never crash the server or leak internals |
| `models.test.js` | Mongoose schema rules and that secrets are never serialised (needs no database) |

## Not covered

The real Mongoose queries inside `repositories/` are not exercised here — that would need
a database (for example `mongodb-memory-server`). The tests prove the API logic around them.
__SAFEREACH_EOF__
echo "  wrote tests/README.md"
for f in models/SOSAlert.js models/Incident.js repositories/SOSAlertRepository.js repositories/IncidentRepository.js repositories/UserRepository.js services/BranchScope.js services/CheckInSweeper.js routes/sosRoutes.js routes/incidentRoutes.js routes/coordinatorRoutes.js routes/adminRoutes.js tests/helpers/fakes.js tests/admin.api.test.js tests/branches.api.test.js; do node --check "$f" || { echo "SYNTAX ERROR in $f"; exit 1; }; done
echo
echo "Done. Now run:  npm test"
