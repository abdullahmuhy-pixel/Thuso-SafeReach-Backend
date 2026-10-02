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
