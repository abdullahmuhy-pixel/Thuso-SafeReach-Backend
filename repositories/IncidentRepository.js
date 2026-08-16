// repositories/IncidentRepository.js
const Incident = require('../models/Incident');

class IncidentRepository {
  async create(data) {
    return Incident.create(data);
  }

  async findAll({ limit = 50 } = {}) {
    return Incident.find()
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
