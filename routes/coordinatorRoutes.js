// routes/coordinatorRoutes.js — the coordinator dashboard use cases from
// the Task 1 use case diagram (Section 3.1): "View Live Alerts", "Manage
// Member Records", "Generate Incident Reports".
const express = require('express');
const UserRepository = require('../repositories/UserRepository');
const SOSAlertRepository = require('../repositories/SOSAlertRepository');
const IncidentRepository = require('../repositories/IncidentRepository');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate, requireRole('coordinator', 'admin'));

// Single dashboard summary endpoint — active alerts + recent incidents in
// one call, so the coordinator UI doesn't need three separate round trips
// on load.
router.get('/dashboard', async (req, res) => {
  const [alerts, incidents] = await Promise.all([
    SOSAlertRepository.findActive(),
    IncidentRepository.findAll({ limit: 20 }),
  ]);
  return res.json({ activeAlerts: alerts, recentIncidents: incidents });
});

router.get('/members', async (req, res) => {
  const members = await UserRepository.list({ role: 'member' });
  return res.json(members);
});

module.exports = router;
