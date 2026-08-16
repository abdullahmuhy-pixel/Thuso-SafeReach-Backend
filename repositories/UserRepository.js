// repositories/UserRepository.js
// Repository pattern (Task 1, Section 4.4): route handlers never touch
// Mongoose/User directly — they go through here. This keeps the API layer
// testable without a live database connection, and means the database
// implementation can change without touching route logic.
const User = require('../models/User');

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

  async findCoordinatorsByBranch(branchId) {
    return User.find({ role: 'coordinator', ngoBranch: branchId });
  }

  async updateRole(id, role) {
    return User.findByIdAndUpdate(id, { role }, { new: true });
  }

  async list({ role } = {}) {
    const filter = role ? { role } : {};
    return User.find(filter).select('-passwordHash');
  }
}

// Exported as a single shared instance — every route imports the same
// repository object, consistent with how the rest of the data layer works.
module.exports = new UserRepository();
