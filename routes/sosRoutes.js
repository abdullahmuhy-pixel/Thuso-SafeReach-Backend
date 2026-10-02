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
