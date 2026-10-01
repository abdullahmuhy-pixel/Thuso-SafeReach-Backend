// repositories/BranchRepository.js
const NGOBranch = require('../models/NGOBranch');

class BranchRepository {
  async list() {
    return NGOBranch.find().sort({ branchName: 1 });
  }

  async findById(id) {
    return NGOBranch.findById(id);
  }

  async findByName(branchName) {
    return NGOBranch.findOne({ branchName });
  }

  async create(data) {
    return NGOBranch.create(data);
  }
}

module.exports = new BranchRepository();
