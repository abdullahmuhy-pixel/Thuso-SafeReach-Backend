// models/Incident.js — matches INCIDENT entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: {
    type: String,
    enum: ['theft', 'assault', 'accident', 'fire', 'medical', 'checkin', 'other'],
    required: true,
  },
  description: { type: String, required: true, trim: true, maxlength: 1000 },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium',
  },
  location: { type: String, trim: true, default: '' },
  lat: { type: Number, default: null },
  lng: { type: Number, default: null },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  // Branch of the reporting member when the report was made (null = unassigned).
  ngoBranch: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOBranch', default: null },
}, { timestamps: { createdAt: 'reportedAt', updatedAt: false } });

module.exports = mongoose.model('Incident', incidentSchema);
