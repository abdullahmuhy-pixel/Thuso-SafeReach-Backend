// repositories/CheckInRepository.js
const CheckIn = require('../models/CheckIn');

class CheckInRepository {
  async create(data) {
    return CheckIn.create(data);
  }

  async findById(id) {
    return CheckIn.findById(id);
  }

  async findActiveForUser(userId) {
    return CheckIn.findOne({ userId, status: 'active' });
  }

  async markSafe(id) {
    return CheckIn.findByIdAndUpdate(id, { status: 'safe' }, { new: true });
  }

  async markEscalated(id) {
    return CheckIn.findByIdAndUpdate(id, { status: 'escalated' }, { new: true });
  }

  async extend(id, extraMinutes) {
    const checkIn = await CheckIn.findById(id);
    if (!checkIn) return null;
    checkIn.expiresAt = new Date(checkIn.expiresAt.getTime() + extraMinutes * 60000);
    await checkIn.save();
    return checkIn;
  }

  // Used by the escalation sweep job (see services/CheckInSweeper.js)
  async findAllExpiredActive() {
    return CheckIn.find({ status: 'active', expiresAt: { $lte: new Date() } });
  }
}

module.exports = new CheckInRepository();
