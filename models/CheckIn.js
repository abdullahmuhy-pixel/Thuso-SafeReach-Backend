// models/CheckIn.js — matches CHECKIN entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const checkInSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  startTime: { type: Date, required: true, default: Date.now },
  durationMinutes: { type: Number, required: true, min: 5, max: 24 * 60 },
  expiresAt: { type: Date, required: true },
  destination: { type: String, trim: true, default: '' },
  status: {
    type: String,
    enum: ['active', 'safe', 'escalated'],
    default: 'active',
  },
  lat: { type: Number, default: null },
  lng: { type: Number, default: null },
  // Record-keeping, so coordinators can see every check-in and how it ended
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
  extendedMinutes: { type: Number, default: 0 },
  extensionCount: { type: Number, default: 0 },
  safeAt: { type: Date, default: null },
  escalatedAt: { type: Date, default: null },
}, { timestamps: { createdAt: true, updatedAt: true } });

// Fast lookup of a member's currently-active check-in
checkInSchema.index({ userId: 1, status: 1 });
// Newest-first history lists for the coordinator dashboard and the member
checkInSchema.index({ startTime: -1 });

module.exports = mongoose.model('CheckIn', checkInSchema);
