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
