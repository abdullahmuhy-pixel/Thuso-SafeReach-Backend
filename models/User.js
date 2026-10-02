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

  // ── Two-factor authentication (coordinators and admins only) ───────────
  totpEnabled: { type: Boolean, default: false },
  // These three are never returned by normal queries (select: false) — code
  // that needs them asks for them explicitly (UserRepository.findByIdWith2FA).
  totpSecret: { type: String, default: null, select: false },          // AES-GCM encrypted
  totpPendingSecret: { type: String, default: null, select: false },   // during setup, before the first code is confirmed
  recoveryHashes: { type: [String], default: [], select: false },      // SHA-256 of unused recovery codes
  totpLastStep: { type: Number, default: null },                       // replay protection
  totpFailures: { type: Number, default: 0 },
  totpLockedUntil: { type: Date, default: null },
}, { timestamps: { createdAt: 'createdAt', updatedAt: false } });

// Never serialise the password hash or 2FA secrets back to the client
userSchema.methods.toSafeJSON = function () {
  const { _id, fullName, phoneNumber, role, createdAt, ngoBranch } = this;
  return {
    id: _id, fullName, phoneNumber, role, createdAt,
    ngoBranch: ngoBranch || null,
    active: this.active !== false,
    twoFactorEnabled: this.totpEnabled === true,
  };
};

module.exports = mongoose.model('User', userSchema);
