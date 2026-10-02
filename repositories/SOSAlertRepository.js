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
