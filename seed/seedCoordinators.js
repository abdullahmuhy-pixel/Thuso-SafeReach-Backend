// seed/seedCoordinators.js — Run ONCE during setup to create the first
// coordinator and admin accounts. There is no public registration endpoint
// for these roles; after this runs, new coordinators are created by an
// admin through POST /api/admin/users.
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const NGOBranch = require('../models/NGOBranch');

const SEED_BRANCH = { branchName: 'Thuso Johannesburg CBD', region: 'Gauteng' };

const SEED_USERS = [
  {
    fullName: 'Thuso Admin',
    phoneNumber: '+27110000001',
    password: 'AdminPass123!',
    role: 'admin',
  },
  {
    fullName: 'Nomvula Coordinator',
    phoneNumber: '+27110000002',
    password: 'CoordPass123!',
    role: 'coordinator',
  },
];

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);

  let branch = await NGOBranch.findOne({ branchName: SEED_BRANCH.branchName });
  if (!branch) branch = await NGOBranch.create(SEED_BRANCH);

  for (const u of SEED_USERS) {
    const existing = await User.findOne({ phoneNumber: u.phoneNumber });
    if (existing) {
      console.log(`[seed] ${u.phoneNumber} already exists — skipping`);
      continue;
    }
    const passwordHash = await bcrypt.hash(u.password, 12);
    await User.create({
      fullName: u.fullName,
      phoneNumber: u.phoneNumber,
      passwordHash,
      role: u.role,
      ngoBranch: u.role === 'coordinator' ? branch._id : null,
    });
    console.log(`[seed] Created ${u.role}: ${u.phoneNumber}`);
  }

  console.log('[seed] Done. Remember to change these passwords after first login.');
  process.exit(0);
}

seed().catch(err => {
  console.error('[seed] Failed:', err);
  process.exit(1);
});
