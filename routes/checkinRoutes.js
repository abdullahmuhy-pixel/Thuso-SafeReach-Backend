// routes/checkinRoutes.js — mirrors the SafeReach frontend check-in timer
// (index.html: showCheckin/startCheckin/extendCheckin/imSafe) server-side,
// so the timer is authoritative even if the member's app is closed. The
// CheckInSweeper service (services/CheckInSweeper.js) escalates any
// check-in that expires without the member confirming here.
const express = require('express');
const CheckInRepository = require('../repositories/CheckInRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, isValid } = require('../middleware/validators');

const router = express.Router();
router.use(authenticate, requireRole('member'));

router.post('/', validateBody({ destination: 'destination' }), async (req, res) => {
  const { durationMinutes, destination, lat, lng } = req.body;
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
  });

  return res.status(201).json({ success: true, checkIn });
});

router.get('/active', async (req, res) => {
  const checkIn = await CheckInRepository.findActiveForUser(req.user._id);
  return res.json({ checkIn: checkIn || null });
});

router.patch('/:id/extend', async (req, res) => {
  const minutes = Number(req.body.minutes) || 15;
  const checkIn = await CheckInRepository.findById(req.params.id);
  if (!checkIn || String(checkIn.userId) !== String(req.user._id)) {
    return res.status(404).json({ error: 'Check-in not found' });
  }
  const updated = await CheckInRepository.extend(req.params.id, minutes);
  return res.json({ success: true, checkIn: updated });
});

router.patch('/:id/safe', async (req, res) => {
  const checkIn = await CheckInRepository.findById(req.params.id);
  if (!checkIn || String(checkIn.userId) !== String(req.user._id)) {
    return res.status(404).json({ error: 'Check-in not found' });
  }
  const updated = await CheckInRepository.markSafe(req.params.id);
  return res.json({ success: true, checkIn: updated });
});

module.exports = router;
