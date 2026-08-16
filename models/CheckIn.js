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
}, { timestamps: { createdAt: true, updatedAt: true } });

// Fast lookup of a member's currently-active check-in
checkInSchema.index({ userId: 1, status: 1 });

module.exports = mongoose.model('CheckIn', checkInSchema);
