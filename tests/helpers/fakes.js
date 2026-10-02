// tests/helpers/fakes.js
// In-memory stand-ins for the repository layer, so the whole HTTP API can be
// tested (real Express, real routes, real middleware, real JWT + bcrypt) with
// no MongoDB connection. This is exactly what the repository pattern from the
// Task 1 design (Section 4.4) makes possible: swap the data layer, keep the API.
const path = require('path');
const Module = require('module');

const ROOT = path.join(__dirname, '..', '..');

let seq = 1;
const oid = () => (seq++).toString(16).padStart(24, '0'); // always a valid 24-char hex ObjectId

const state = { users: [], branches: [], alerts: [], incidents: [], checkIns: [], dispatched: [], failNext: new Set() };

// Lets a test make one repository method throw once, to prove the API
// survives an unexpected failure instead of crashing.
const guard = name => { if (state.failNext.delete(name)) throw new Error('simulated failure in ' + name); };

const SECRET_FIELDS = ['passwordHash', 'totpSecret', 'totpPendingSecret', 'recoveryHashes'];
const withoutSecrets = u => { const c = { ...u }; SECRET_FIELDS.forEach(f => delete c[f]); return c; };

function decorate(u) {
  if (!u) return null;
  Object.defineProperty(u, 'toSafeJSON', {
    enumerable: false, configurable: true,
    value: () => ({
      id: u._id, fullName: u.fullName, phoneNumber: u.phoneNumber, role: u.role, createdAt: u.createdAt,
      ngoBranch: u.ngoBranch || null, active: u.active !== false, twoFactorEnabled: u.totpEnabled === true,
    }),
  });
  return u;
}
const findUser = id => state.users.find(u => u._id === String(id));

const UserRepository = {
  async create(d) {
    guard('UserRepository.create');
    const u = {
      _id: oid(), createdAt: new Date(), active: true, passwordChangedAt: null, ngoBranch: null,
      totpEnabled: false, totpSecret: null, totpPendingSecret: null, recoveryHashes: [],
      totpLastStep: null, totpFailures: 0, totpLockedUntil: null, ...d,
    };
    state.users.push(u);
    return decorate(u);
  },
  async findByPhone(phoneNumber) { guard('UserRepository.findByPhone'); return decorate(state.users.find(u => u.phoneNumber === phoneNumber) || null); },
  async findById(id) { return decorate(findUser(id) || null); },
  async findByIdWith2FA(id) { return decorate(findUser(id) || null); },
  async findCoordinatorsByBranch(b) { return state.users.filter(u => u.role === 'coordinator' && u.ngoBranch === b); },
  async updateRole(id, role) { findUser(id).role = role; return decorate(findUser(id)); },
  async setActive(id, active) { findUser(id).active = active; return decorate(findUser(id)); },
  async setBranch(id, branchId) { findUser(id).ngoBranch = branchId; return decorate(findUser(id)); },
  async updatePassword(id, passwordHash) { const u = findUser(id); u.passwordHash = passwordHash; u.passwordChangedAt = new Date(); return decorate(u); },
  async list({ role, branchId } = {}) {
    return state.users
      .filter(u => (!role || u.role === role) && (!branchId || !u.ngoBranch || String(u.ngoBranch) === String(branchId)))
      .map(withoutSecrets);
  },
  async setPendingSecret(id, s) { findUser(id).totpPendingSecret = s; },
  async enableTotp(id, secret, hashes, step) {
    Object.assign(findUser(id), { totpEnabled: true, totpSecret: secret, totpPendingSecret: null, recoveryHashes: hashes, totpLastStep: step, totpFailures: 0, totpLockedUntil: null });
  },
  async disableTotp(id, { revokeSessions = false } = {}) {
    const u = findUser(id);
    Object.assign(u, { totpEnabled: false, totpSecret: null, totpPendingSecret: null, recoveryHashes: [], totpLastStep: null, totpFailures: 0, totpLockedUntil: null });
    if (revokeSessions) u.passwordChangedAt = new Date();
  },
  async claimTotpStep(id, step) { const u = findUser(id); if (u.totpLastStep === null || u.totpLastStep < step) { u.totpLastStep = step; return true; } return false; },
  async consumeRecoveryHash(id, hash) { const u = findUser(id); const i = u.recoveryHashes.indexOf(hash); if (i < 0) return false; u.recoveryHashes.splice(i, 1); return true; },
  async resetTotpFailures(id) { const u = findUser(id); u.totpFailures = 0; u.totpLockedUntil = null; },
  async recordTotpFailure(id, limit, lockMs) {
    const u = findUser(id); u.totpFailures += 1;
    if (u.totpFailures >= limit) { u.totpFailures = 0; u.totpLockedUntil = new Date(Date.now() + lockMs); return true; }
    return false;
  },
};

const BranchRepository = {
  async list() { return [...state.branches].sort((a, b) => a.branchName.localeCompare(b.branchName)); },
  async findById(id) { return state.branches.find(b => b._id === String(id)) || null; },
  async findByName(name) { return state.branches.find(b => b.branchName === name) || null; },
  async create(d) { const b = { _id: oid(), ...d }; state.branches.push(b); return b; },
};

const populate = userId => { const u = findUser(userId); return u ? { _id: u._id, fullName: u.fullName, phoneNumber: u.phoneNumber } : null; };

const SOSAlertRepository = {
  async create(d) {
    const a = { _id: oid(), status: 'active', triggeredAt: new Date(), resolvedBy: null, resolvedAt: null, ...d };
    state.alerts.push(a); return a;
  },
  async findById(id) { return state.alerts.find(a => a._id === String(id)) || null; },
  async findActive({ branchId } = {}) {
    return state.alerts
      .filter(a => a.status === 'active' && (!branchId || !a.ngoBranch || String(a.ngoBranch) === String(branchId)))
      .map(a => ({ ...a, userId: populate(a.userId) }));
  },
  async resolve(id, by) {
    const a = state.alerts.find(x => x._id === String(id)); if (!a) return null;
    Object.assign(a, { status: 'resolved', resolvedBy: by, resolvedAt: new Date() }); return a;
  },
};

const IncidentRepository = {
  async create(d) { const i = { _id: oid(), reportedAt: new Date(), reviewedBy: null, ...d }; state.incidents.push(i); return i; },
  async findById(id) { return state.incidents.find(i => i._id === String(id)) || null; },
  async findAll({ limit = 50, branchId } = {}) {
    return state.incidents
      .filter(i => !branchId || !i.ngoBranch || String(i.ngoBranch) === String(branchId))
      .slice(-limit).reverse().map(i => ({ ...i, userId: populate(i.userId) }));
  },
  async findByUser(userId) { return state.incidents.filter(i => String(i.userId) === String(userId)); },
  async markReviewed(id, by) { const i = state.incidents.find(x => x._id === String(id)); if (!i) return null; i.reviewedBy = by; return i; },
};

const CheckInRepository = {
  async create(d) { const c = { _id: oid(), status: 'active', startTime: new Date(), ...d }; state.checkIns.push(c); return c; },
  async findById(id) { return state.checkIns.find(c => c._id === String(id)) || null; },
  async findActiveForUser(userId) { return state.checkIns.find(c => String(c.userId) === String(userId) && c.status === 'active') || null; },
  async markSafe(id) { const c = state.checkIns.find(x => x._id === String(id)); c.status = 'safe'; return c; },
  async extend(id, minutes) { const c = state.checkIns.find(x => x._id === String(id)); c.expiresAt = new Date(c.expiresAt.getTime() + minutes * 60000); return c; },
  async findAllExpiredActive() { return state.checkIns.filter(c => c.status === 'active' && c.expiresAt <= new Date()); },
  async markEscalated(id) { state.checkIns.find(x => x._id === String(id)).status = 'escalated'; },
};

const NotificationDispatcher = { dispatchAlert: async alert => { state.dispatched.push(alert); } };

function reset() {
  for (const k of ['users', 'branches', 'alerts', 'incidents', 'checkIns', 'dispatched']) state[k].length = 0;
  state.failNext.clear();
}

// Replace modules in Node's require cache so the real route code receives the
// fakes (and third-party pieces we don't want hitting the network/DB).
function replaceModule(resolvedFile, exports) {
  const m = new Module(resolvedFile, null);
  m.filename = resolvedFile; m.loaded = true; m.exports = exports;
  require.cache[resolvedFile] = m;
}
const projectFile = rel => require.resolve(path.join(ROOT, rel));
const packageFile = name => require.resolve(name, { paths: [ROOT] });

function installAll() {
  replaceModule(projectFile('repositories/UserRepository'), UserRepository);
  replaceModule(projectFile('repositories/BranchRepository'), BranchRepository);
  replaceModule(projectFile('repositories/SOSAlertRepository'), SOSAlertRepository);
  replaceModule(projectFile('repositories/IncidentRepository'), IncidentRepository);
  replaceModule(projectFile('repositories/CheckInRepository'), CheckInRepository);
  replaceModule(projectFile('services/NotificationDispatcher'), NotificationDispatcher);
  replaceModule(projectFile('config/db'), async () => {});
  // The real rate limiters would start rejecting tests after 10 logins from
  // 127.0.0.1; they are a library concern, not something we are testing here.
  replaceModule(packageFile('express-rate-limit'), () => (req, res, next) => next());
}

module.exports = { state, reset, installAll, UserRepository, BranchRepository, ROOT };
