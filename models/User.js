// models/User.js — matches USER entity in the Task 1 ER diagram (Section 3.4)
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  phoneNumber: { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  role: {
    type: String,
    enum: ['member', 'coordinator', 'admin'],
    default: 'member',
    required: true,
  },
  // Only populated for role === 'coordinator'
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
  // Soft-delete flag: deactivated accounts cannot sign in, but their check-ins,
  // alerts and reports stay in the database for the audit trail.
  // (Accounts created before this field existed are treated as active.)
  active: { type: Boolean, default: true },
  // Tokens issued before this moment are rejected (see middleware/auth.js)
  passwordChangedAt: { type: Date, default: null },
}, { timestamps: { createdAt: 'createdAt', updatedAt: false } });

// Never serialise the password hash back to the client
userSchema.methods.toSafeJSON = function () {
  const { _id, fullName, phoneNumber, role, createdAt, ngoBranch } = this;
  return { id: _id, fullName, phoneNumber, role, createdAt, ngoBranch: ngoBranch || null, active: this.active !== false };
};

module.exports = mongoose.model('User', userSchema);
