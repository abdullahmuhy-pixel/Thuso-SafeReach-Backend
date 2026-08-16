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
}, { timestamps: { createdAt: 'createdAt', updatedAt: false } });

// Never serialise the password hash back to the client
userSchema.methods.toSafeJSON = function () {
  const { _id, fullName, phoneNumber, role, createdAt } = this;
  return { id: _id, fullName, phoneNumber, role, createdAt };
};

module.exports = mongoose.model('User', userSchema);
