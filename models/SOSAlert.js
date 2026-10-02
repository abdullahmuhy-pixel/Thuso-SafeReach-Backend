// models/SOSAlert.js — matches SOS_ALERT entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const sosAlertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  checkInId: { type: mongoose.Schema.Types.ObjectId, ref: 'CheckIn', default: null },
  triggeredAt: { type: Date, required: true, default: Date.now },
  triggerSource: {
    type: String,
    enum: ['manual', 'shake', 'checkin_timeout'],
    default: 'manual',
  },
  lat: { type: Number, default: null },
  lng: { type: Number, default: null },
  status: {
    type: String,
    enum: ['active', 'resolved'],
    default: 'active',
  },
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedAt: { type: Date, default: null },
  // Branch of the member at the moment the alert was raised (null = member not
  // assigned to a branch). Stored on the alert so later reassignments don't
  // change who was responsible for it.
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
}, { timestamps: { createdAt: false, updatedAt: true } });

sosAlertSchema.index({ status: 1, triggeredAt: -1 });

module.exports = mongoose.model('SOSAlert', sosAlertSchema);
