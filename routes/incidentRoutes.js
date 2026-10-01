// routes/incidentRoutes.js — mirrors the SafeReach frontend "Report an
// Incident" feature (index.html: showReport/submitReport). The frontend
// currently only saves reports to localStorage; this endpoint is what lets
// Task 2 sync them to the cloud so a coordinator can actually see them,
// which is the whole point of building the coordinator layer.
const express = require('express');
const IncidentRepository = require('../repositories/IncidentRepository');
const { authenticate, requireRole } = require('../middleware/auth');
const { validateBody, validateParams, isValid } = require('../middleware/validators');

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
  const incidents = await IncidentRepository.findAll();
  return res.json(incidents);
});

router.patch(
  '/:id/review',
  authenticate,
  requireRole('coordinator', 'admin'),
  validateParams({ id: 'mongoId' }),
  async (req, res) => {
    const incident = await IncidentRepository.markReviewed(req.params.id, req.user._id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    return res.json({ success: true, incident });
  }
);

module.exports = router;
