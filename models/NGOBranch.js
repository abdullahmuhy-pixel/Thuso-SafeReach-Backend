// models/NGOBranch.js — matches NGO_BRANCH entity in the Task 1 ER diagram
const mongoose = require('mongoose');

const ngoBranchSchema = new mongoose.Schema({
  branchName: { type: String, required: true, trim: true },
  region: { type: String, required: true, trim: true },
}, { timestamps: false });

module.exports = mongoose.model('NGOBranch', ngoBranchSchema);
