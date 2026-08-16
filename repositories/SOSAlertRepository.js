// repositories/SOSAlertRepository.js
const SOSAlert = require('../models/SOSAlert');

class SOSAlertRepository {
  async create(data) {
    return SOSAlert.create(data);
  }

  async findById(id) {
    return SOSAlert.findById(id).populate('userId', 'fullName phoneNumber');
  }

  async findActive() {
    return SOSAlert.find({ status: 'active' })
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
