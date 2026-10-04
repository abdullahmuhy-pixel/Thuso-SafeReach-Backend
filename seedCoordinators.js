// seed/seedCoordinators.js — Run ONCE during setup to create the first
// coordinator and admin accounts. There is no public registration endpoint
// for these roles; after this runs, new coordinators are created by an
// admin through POST /api/admin/users.
//
// No passwords are stored in this file (the repository is public).
// For each account the password comes from an environment variable:
//   SEED_ADMIN_PASSWORD        for the admin
//   SEED_COORDINATOR_PASSWORD  for the coordinator
// If a variable is not set, a random one-time password is generated and
// printed ONCE in the terminal. Copy it then and change it after first login.
require('dotenv').config();
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const NGOBranch = require('../models/NGOBranch');

const SEED_BRANCH = { branchName: 'Thuso Johannesburg CBD', region: 'Gauteng' };

const SEED_USERS = [
  {
    fullName: 'Thuso Admin',
    phoneNumber: '+27110000001',
    passwordEnv: 'SEED_ADMIN_PASSWORD',
    role: 'admin',
  },
  {
    fullName: 'Nomvula Coordinator',
    phoneNumber: '+27110000002',
    passwordEnv: 'SEED_COORDINATOR_PASSWORD',
    role: 'coordinator',
  },
];

// Random password that meets the app's rules: 8-72 characters with a capital
// letter, a digit and one of @ $ ! % * ? &
function randomPassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const special = '@$!%*?&';
  const pick = set => set[crypto.randomInt(set.length)];
  const chars = [pick(upper), pick(digits), pick(special)];
  const all = upper + lower + digits;
  while (chars.length < 16) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

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
    let password = process.env[u.passwordEnv];
    let generated = false;
    if (!password) {
      password = randomPassword();
      generated = true;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({
      fullName: u.fullName,
      phoneNumber: u.phoneNumber,
      passwordHash,
      role: u.role,
      ngoBranch: u.role === 'coordinator' ? branch._id : null,
    });
    console.log(`[seed] Created ${u.role}: ${u.phoneNumber}`);
    if (generated) {
      console.log(`[seed] One-time password for ${u.phoneNumber}: ${password}`);
      console.log('[seed] Shown only once. Copy it now.');
    }
  }

  console.log('[seed] Done. Change these passwords after first login.');
  process.exit(0);
}

seed().catch(err => {
  console.error('[seed] Failed:', err);
  process.exit(1);
});
