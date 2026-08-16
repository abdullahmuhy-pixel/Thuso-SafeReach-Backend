// models/Notification.js — matches NOTIFICATION entity in the Task 1 ER diagram.
// A record here is created every time NotificationService.send() dispatches
// an alert, regardless of which strategy (SMS/push) was used.
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'SOSAlert', required: true },
  channel: { type: String, enum: ['sms', 'push'], required: true },
  sentAt: { type: Date, required: true, default: Date.now },
  deliveryStatus: {
    type: String,
    enum: ['sent', 'failed', 'pending'],
    default: 'pending',
  },
}, { timestamps: false });

module.exports = mongoose.model('Notification', notificationSchema);
