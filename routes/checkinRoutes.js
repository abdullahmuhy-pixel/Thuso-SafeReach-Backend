// routes/checkinRoutes.js — mirrors the SafeReach frontend check-in timer
// (index.html: showCheckin/startCheckin/extendCheckin/imSafe) server-side,
// so the timer is authoritative even if the member's app is closed. The
// CheckInSweeper service (services/CheckInSweeper.js) escalates any
// check-in that expires without the member confirming here.
const express = require('express');
const CheckInRepository = require('../repositories/CheckInRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, validateParams, isValid } = require('../middleware/validators');

const router = express.Router();
router.use(authenticate, requireRole('member'));

router.post('/', validateBody({ destination: 'destination' }), async (req, res) => {
  const { durationMinutes, destination, lat, lng } = req.body;

  if (typeof durationMinutes !== 'number' && typeof durationMinutes !== 'string') {
    return res.status(400).json({ error: 'durationMinutes must be a number' });
  }
  const minutes = Number(durationMinutes);
  if (!Number.isFinite(minutes) || minutes < 5 || minutes > 24 * 60) {
    return res.status(400).json({ error: 'durationMinutes must be between 5 and 1440' });
  }
  if (lat !== undefined && !isValid('latLng', lat)) return res.status(400).json({ error: 'Invalid latitude' });
  if (lng !== undefined && !isValid('latLng', lng)) return res.status(400).json({ error: 'Invalid longitude' });

  const existing = await CheckInRepository.findActiveForUser(req.user._id);
  if (existing) return res.status(409).json({ error: 'A check-in is already active' });

  const checkIn = await CheckInRepository.create({
    userId: req.user._id,
    durationMinutes: minutes,
    expiresAt: new Date(Date.now() + minutes * 60000),
    destination: destination || '',
    lat: lat ?? null,
    lng: lng ?? null,
    ngoBranch: req.user.ngoBranch || null,
  });

  return res.status(201).json({ success: true, checkIn });
});

router.get('/active', async (req, res) => {
  const checkIn = await CheckInRepository.findActiveForUser(req.user._id);
  return res.json({ checkIn: checkIn || null });
});

// The member's own check-in history (every timer they have used)
router.get('/history', async (req, res) => {
  const checkIns = await CheckInRepository.findByUser(req.user._id);
  return res.json({ checkIns });
});

router.patch('/:id/extend', validateParams({ id: 'mongoId' }), async (req, res) => {
  const raw = req.body.minutes === undefined ? 15 : req.body.minutes;
  const minutes = typeof raw === 'number' || typeof raw === 'string' ? Number(raw) : NaN;
  if (!Number.isFinite(minutes) || minutes < 1 || minutes > 720) {
    return res.status(400).json({ error: 'minutes must be between 1 and 720' });
  }

  const checkIn = await CheckInRepository.findById(req.params.id);
  if (!checkIn || String(checkIn.userId) !== String(req.user._id)) {
    return res.status(404).json({ error: 'Check-in not found' });
  }
  if (checkIn.status !== 'active') {
    return res.status(409).json({ error: 'This check-in is no longer active' });
  }
  const updated = await CheckInRepository.extend(req.params.id, minutes);
  return res.json({ success: true, checkIn: updated });
});

// Reads an optional { lat, lng, accuracy } from the body.
// Returns null when no location was sent, or { error } when it is invalid.
function readLocation(body) {
  const { lat, lng, accuracy } = body || {};
  if (lat === undefined && lng === undefined) return null;
  if (!isValid('latLng', lat) || !isValid('latLng', lng)) return { error: 'Invalid latitude or longitude' };
  const la = Number(lat), ln = Number(lng);
  if (Math.abs(la) > 90 || Math.abs(ln) > 180) return { error: 'Invalid latitude or longitude' };
  let acc = null;
  if (accuracy !== undefined && accuracy !== null) {
    acc = Number(accuracy);
    if (!Number.isFinite(acc) || acc < 0 || acc > 100000) return { error: 'Invalid accuracy' };
    acc = Math.round(acc);
  }
  return { lat: la, lng: ln, accuracy: acc };
}

// The member's phone reports its position every few minutes while the timer
// runs, so a missed check-in can be escalated with a recent location.
router.patch('/:id/location', validateParams({ id: 'mongoId' }), async (req, res) => {
  const loc = readLocation(req.body);
  if (!loc) return res.status(400).json({ error: 'lat and lng are required' });
  if (loc.error) return res.status(400).json({ error: loc.error });

  const checkIn = await CheckInRepository.findById(req.params.id);
  if (!checkIn || String(checkIn.userId) !== String(req.user._id)) {
    return res.status(404).json({ error: 'Check-in not found' });
  }
  if (checkIn.status !== 'active') {
    return res.status(409).json({ error: 'This check-in is no longer active' });
  }
  const updated = await CheckInRepository.addLocation(req.params.id, loc);
  return res.json({ success: true, checkIn: updated });
});

router.patch('/:id/safe', validateParams({ id: 'mongoId' }), async (req, res) => {
  const loc = readLocation(req.body);
  if (loc && loc.error) return res.status(400).json({ error: loc.error });

  const checkIn = await CheckInRepository.findById(req.params.id);
  if (!checkIn || String(checkIn.userId) !== String(req.user._id)) {
    return res.status(404).json({ error: 'Check-in not found' });
  }
  if (checkIn.status === 'safe') return res.json({ success: true, checkIn });
  const updated = await CheckInRepository.markSafe(req.params.id, loc);
  return res.json({ success: true, checkIn: updated });
});

module.exports = router;
