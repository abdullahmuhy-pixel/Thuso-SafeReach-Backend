// repositories/CheckInRepository.js
const CheckIn = require('../models/CheckIn');

// Same rule as the alert and incident repositories: a coordinator sees their
// branch's check-ins plus check-ins from members not assigned to a branch.
const branchFilter = branchId => (branchId ? { $or: [{ ngoBranch: branchId }, { ngoBranch: null }] } : {});

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

  // loc is optional: { lat, lng, accuracy } where the member pressed "I'm safe"
  async markSafe(id, loc) {
    const update = { status: 'safe', safeAt: new Date() };
    if (loc) {
      update.safeLat = loc.lat;
      update.safeLng = loc.lng;
      update.lastLat = loc.lat;
      update.lastLng = loc.lng;
      update.lastAccuracy = loc.accuracy ?? null;
      update.lastLocationAt = update.safeAt;
    }
    return CheckIn.findByIdAndUpdate(id, update, { new: true });
  }

  // Position update from the member's phone while the timer is running
  async addLocation(id, { lat, lng, accuracy = null }) {
    const at = new Date();
    return CheckIn.findByIdAndUpdate(id, {
      lastLat: lat, lastLng: lng, lastAccuracy: accuracy, lastLocationAt: at,
      $push: { locationTrail: { $each: [{ lat, lng, accuracy, at }], $slice: -CheckIn.LOCATION_TRAIL_MAX } },
    }, { new: true });
  }

  async markEscalated(id) {
    return CheckIn.findByIdAndUpdate(id, { status: 'escalated', escalatedAt: new Date() }, { new: true });
  }

  async extend(id, extraMinutes) {
    const checkIn = await CheckIn.findById(id);
    if (!checkIn) return null;
    checkIn.expiresAt = new Date(checkIn.expiresAt.getTime() + extraMinutes * 60000);
    checkIn.extendedMinutes = (checkIn.extendedMinutes || 0) + extraMinutes;
    checkIn.extensionCount = (checkIn.extensionCount || 0) + 1;
    await checkIn.save();
    return checkIn;
  }

  // Check-in log for the coordinator dashboard, newest first
  async findAll({ limit = 50, branchId, status } = {}) {
    const q = branchFilter(branchId);
    if (status) q.status = status;
    return CheckIn.find(q)
      .sort({ startTime: -1 })
      .limit(limit)
      .populate('userId', 'fullName phoneNumber');
  }

  // A member's own check-in history, newest first
  async findByUser(userId, limit = 50) {
    return CheckIn.find({ userId }).sort({ startTime: -1 }).limit(limit);
  }

  // Used by the escalation sweep job (see services/CheckInSweeper.js)
  async findAllExpiredActive() {
    return CheckIn.find({ status: 'active', expiresAt: { $lte: new Date() } });
  }
}

module.exports = new CheckInRepository();
