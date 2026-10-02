// repositories/UserRepository.js
// Repository pattern (Task 1, Section 4.4): route handlers never touch
// Mongoose/User directly — they go through here. This keeps the API layer
// testable without a live database connection, and means the database
// implementation can change without touching route logic.
const User = require('../models/User');

const WITH_2FA = '+totpSecret +totpPendingSecret +recoveryHashes';

class UserRepository {
  async create(userData) {
    return User.create(userData);
  }

  async findByPhone(phoneNumber) {
    return User.findOne({ phoneNumber });
  }

  async findById(id) {
    return User.findById(id);
  }

  // Same as findById but also loads the hidden 2FA secret fields.
  async findByIdWith2FA(id) {
    return User.findById(id).select(WITH_2FA);
  }

  async findCoordinatorsByBranch(branchId) {
    return User.find({ role: 'coordinator', ngoBranch: branchId });
  }

  async updateRole(id, role) {
    return User.findByIdAndUpdate(id, { role }, { new: true });
  }

  // Soft delete / restore — records stay, sign-in stops.
  async setActive(id, active) {
    return User.findByIdAndUpdate(id, { active }, { new: true });
  }

  async setBranch(id, branchId) {
    return User.findByIdAndUpdate(id, { ngoBranch: branchId }, { new: true });
  }

  // Also stamps passwordChangedAt so older sessions stop working.
  async updatePassword(id, passwordHash) {
    return User.findByIdAndUpdate(
      id,
      { passwordHash, passwordChangedAt: new Date() },
      { new: true }
    );
  }

  // branchId set -> only that branch's users plus users with no branch
  // (used for the coordinator's member list).
  async list({ role, branchId } = {}) {
    const filter = role ? { role } : {};
    if (branchId) filter.$or = [{ ngoBranch: branchId }, { ngoBranch: null }];
    return User.find(filter)
      .select('-passwordHash')
      .populate('ngoBranch', 'branchName region')
      .sort({ createdAt: -1 });
  }

  // ── 2FA ───────────────────────────────────────────────────────────────
  async setPendingSecret(id, encryptedSecret) {
    return User.findByIdAndUpdate(id, { totpPendingSecret: encryptedSecret }, { new: true });
  }

  async enableTotp(id, encryptedSecret, recoveryHashes, step) {
    return User.findByIdAndUpdate(id, {
      totpEnabled: true,
      totpSecret: encryptedSecret,
      totpPendingSecret: null,
      recoveryHashes,
      totpLastStep: step,
      totpFailures: 0,
      totpLockedUntil: null,
    }, { new: true });
  }

  // revokeSessions: also invalidate every existing session (used by admin reset).
  async disableTotp(id, { revokeSessions = false } = {}) {
    const update = {
      totpEnabled: false,
      totpSecret: null,
      totpPendingSecret: null,
      recoveryHashes: [],
      totpLastStep: null,
      totpFailures: 0,
      totpLockedUntil: null,
    };
    if (revokeSessions) update.passwordChangedAt = new Date();
    return User.findByIdAndUpdate(id, update, { new: true });
  }

  // Atomic "use this 30-second step once": true only for the first caller.
  async claimTotpStep(id, step) {
    const r = await User.updateOne(
      { _id: id, $or: [{ totpLastStep: null }, { totpLastStep: { $lt: step } }] },
      { totpLastStep: step }
    );
    return r.modifiedCount === 1;
  }

  // Atomic: removes the hash and reports whether it was still unused.
  async consumeRecoveryHash(id, hash) {
    const r = await User.updateOne({ _id: id, recoveryHashes: hash }, { $pull: { recoveryHashes: hash } });
    return r.modifiedCount === 1;
  }

  async resetTotpFailures(id) {
    return User.updateOne({ _id: id }, { totpFailures: 0, totpLockedUntil: null });
  }

  // Returns true if this failure triggered a lockout.
  async recordTotpFailure(id, limit, lockMs) {
    const u = await User.findByIdAndUpdate(id, { $inc: { totpFailures: 1 } }, { new: true });
    if (u && u.totpFailures >= limit) {
      await User.updateOne({ _id: id }, { totpFailures: 0, totpLockedUntil: new Date(Date.now() + lockMs) });
      return true;
    }
    return false;
  }
}

// Exported as a single shared instance — every route imports the same
// repository object, consistent with how the rest of the data layer works.
module.exports = new UserRepository();
