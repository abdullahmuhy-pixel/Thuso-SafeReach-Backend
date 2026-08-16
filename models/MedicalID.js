// models/MedicalID.js — matches MEDICAL_ID entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const medicalIdSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  bloodType: { type: String, trim: true, default: '' },
  allergies: { type: String, trim: true, default: '' },
  medications: { type: String, trim: true, default: '' },
  conditions: { type: String, trim: true, default: '' },
  emergencyContactName: { type: String, trim: true, default: '' },
  emergencyContactPhone: { type: String, trim: true, default: '' },
  notes: { type: String, trim: true, default: '' },
}, { timestamps: true });

module.exports = mongoose.model('MedicalID', medicalIdSchema);
