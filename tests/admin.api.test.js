// Admin tools: accounts, roles, branches, deactivation, password and 2FA resets.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, AuthService, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const newCoordinator = { fullName: 'New Coordinator', phoneNumber: '+27820001111', password: 'Coord@1234', role: 'coordinator' };

describe('access control', () => {
  it('only admins may use /api/admin', async () => {
    const coord = await addUser({ role: 'coordinator' });
    const member = await addUser();
    for (const who of [coord, member]) {
      assert.equal((await app.api('GET', '/api/admin/users', { token: who.token })).status, 403);
      assert.equal((await app.api('POST', '/api/admin/users', { token: who.token, body: newCoordinator })).status, 403);
    }
    assert.equal((await app.api('GET', '/api/admin/users')).status, 401);
  });
});

describe('creating accounts', () => {
  it('creates a coordinator who can then sign in at the coordinator login', async () => {
    const admin = await addUser({ role: 'admin' });
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: newCoordinator });
    assert.equal(r.status, 201);
    assert.equal(r.body.user.role, 'coordinator');
    const login = await app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: newCoordinator.phoneNumber, password: newCoordinator.password } });
    assert.equal(login.status, 200);
    assert.ok(login.body.token);
  });

  it('puts a coordinator in a branch that exists, and rejects ones that do not', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'Thuso Soweto', region: 'Gauteng' } });
    const ok = await app.api('POST', '/api/admin/users', { token: admin.token, body: { ...newCoordinator, ngoBranch: branch._id } });
    assert.equal(ok.status, 201);
    assert.equal(ok.body.user.ngoBranch, branch._id);
    for (const ngoBranch of ['not-an-id', 'e'.repeat(24), ['x']]) {
      const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { ...newCoordinator, phoneNumber: '+27820002222', ngoBranch } });
      assert.equal(r.status, 400, JSON.stringify(ngoBranch));
    }
  });

  it('can place a new member in a branch', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'West', region: 'Gauteng' } });
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { fullName: 'New Member', phoneNumber: '+27820003333', password: 'Member@1234', role: 'member', ngoBranch: branch._id } });
    assert.equal(r.status, 201);
    assert.equal(r.body.user.ngoBranch, branch._id);
  });

  it('rejects missing password / role, bad role, weak password and duplicates', async () => {
    const admin = await addUser({ role: 'admin' });
    const post = body => app.api('POST', '/api/admin/users', { token: admin.token, body });
    const { password, ...noPassword } = newCoordinator;
    const { role, ...noRole } = newCoordinator;
    assert.equal((await post(noPassword)).status, 400, 'used to crash the server');
    assert.equal((await post(noRole)).status, 400);
    assert.equal((await post({ ...newCoordinator, role: 'superuser' })).status, 400);
    assert.equal((await post({ ...newCoordinator, password: 'weak' })).status, 400);
    assert.equal((await post(newCoordinator)).status, 201);
    assert.equal((await post(newCoordinator)).status, 409);
  });
});

describe('listing accounts', () => {
  it('never exposes password hashes or 2FA secrets', async () => {
    const admin = await addUser({ role: 'admin' });
    const coord = await addUser({ role: 'coordinator' });
    coord.user.totpSecret = 'SUPER-SECRET-VALUE';
    coord.user.recoveryHashes = ['deadbeef'];
    const r = await app.api('GET', '/api/admin/users', { token: admin.token });
    assert.equal(r.status, 200);
    const text = JSON.stringify(r.body);
    for (const leak of ['passwordHash', 'totpSecret', 'SUPER-SECRET-VALUE', 'recoveryHashes', 'deadbeef']) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
  });

  it('filters by role and rejects an invalid filter', async () => {
    const admin = await addUser({ role: 'admin' });
    await addUser({ role: 'coordinator' });
    await addUser();
    assert.equal((await app.api('GET', '/api/admin/users?role=coordinator', { token: admin.token })).body.length, 1);
    assert.equal((await app.api('GET', '/api/admin/users?role=wizard', { token: admin.token })).status, 400);
  });
});

describe('changing roles', () => {
  it('changes another account\'s role', async () => {
    const admin = await addUser({ role: 'admin' });
    const target = await addUser();
    const r = await app.api('PATCH', `/api/admin/users/${target.user._id}/role`, { token: admin.token, body: { role: 'coordinator' } });
    assert.equal(r.status, 200);
    assert.equal(target.user.role, 'coordinator');
  });

  it('will not let an admin change their own role', async () => {
    const admin = await addUser({ role: 'admin' });
    const r = await app.api('PATCH', `/api/admin/users/${admin.user._id}/role`, { token: admin.token, body: { role: 'member' } });
    assert.equal(r.status, 400);
    assert.equal(admin.user.role, 'admin');
  });

  it('validates the id, the role and the target', async () => {
    const admin = await addUser({ role: 'admin' });
    const t = await addUser();
    assert.equal((await app.api('PATCH', '/api/admin/users/nope/role', { token: admin.token, body: { role: 'member' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/role`, { token: admin.token, body: { role: 'wizard' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${'e'.repeat(24)}/role`, { token: admin.token, body: { role: 'member' } })).status, 404);
  });

  it('clears the branch when someone becomes an admin (admins work across all branches), keeps it otherwise', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'North', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    c.user.ngoBranch = branch._id;
    await app.api('PATCH', `/api/admin/users/${c.user._id}/role`, { token: admin.token, body: { role: 'member' } });
    assert.equal(c.user.ngoBranch, branch._id, 'a demoted coordinator stays in their branch');
    await app.api('PATCH', `/api/admin/users/${c.user._id}/role`, { token: admin.token, body: { role: 'admin' } });
    assert.equal(c.user.ngoBranch, null);
  });
});

describe('deactivating and reactivating (soft delete)', () => {
  it('blocks sign-in and kills existing sessions, then restores access', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await addUser({ role: 'coordinator' });
    const patch = active => app.api('PATCH', `/api/admin/users/${c.user._id}/active`, { token: admin.token, body: { active } });
    const login = () => app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: c.phone, password: c.password } });

    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 200);
    assert.equal((await patch(false)).body.user.active, false);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 401, 'existing session is dead');
    assert.equal((await login()).status, 403, 'right password, deactivated');
    assert.equal((await app.api('POST', '/api/coordinator/auth/login', { body: { phoneNumber: c.phone, password: 'Wrong@1234' } })).status, 401, 'wrong password reveals nothing');

    assert.equal((await patch(true)).body.user.active, true);
    assert.equal((await login()).status, 200);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: c.token })).status, 200);
  });

  it('keeps the account\'s records', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    await app.api('POST', '/api/sos', { token: m.token, body: {} });
    await app.api('PATCH', `/api/admin/users/${m.user._id}/active`, { token: admin.token, body: { active: false } });
    assert.equal(state.alerts.length, 1);
    assert.equal(state.users.length, 2);
  });

  it('will not let an admin deactivate themselves, and validates input', async () => {
    const admin = await addUser({ role: 'admin' });
    const t = await addUser();
    assert.equal((await app.api('PATCH', `/api/admin/users/${admin.user._id}/active`, { token: admin.token, body: { active: false } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/active`, { token: admin.token, body: { active: 'false' } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${t.user._id}/active`, { token: admin.token, body: {} })).status, 400);
    assert.equal((await app.api('PATCH', '/api/admin/users/bad/active', { token: admin.token, body: { active: false } })).status, 400);
    assert.equal((await app.api('PATCH', `/api/admin/users/${'e'.repeat(24)}/active`, { token: admin.token, body: { active: false } })).status, 404);
  });
});

describe('NGO branches', () => {
  it('creates, lists (sorted) and de-duplicates branches', async () => {
    const admin = await addUser({ role: 'admin' });
    const add = body => app.api('POST', '/api/admin/branches', { token: admin.token, body });
    assert.equal((await add({ branchName: 'Zulu Branch', region: 'KZN' })).status, 201);
    assert.equal((await add({ branchName: 'Alpha Branch', region: 'Gauteng' })).status, 201);
    assert.equal((await add({ branchName: 'Alpha Branch', region: 'Gauteng' })).status, 409);
    const list = await app.api('GET', '/api/admin/branches', { token: admin.token });
    assert.deepEqual(list.body.map(b => b.branchName), ['Alpha Branch', 'Zulu Branch']);
  });

  it('validates names and regions', async () => {
    const admin = await addUser({ role: 'admin' });
    const add = body => app.api('POST', '/api/admin/branches', { token: admin.token, body });
    assert.equal((await add({ branchName: '<script>', region: 'Gauteng' })).status, 400);
    assert.equal((await add({ branchName: 'Only Name' })).status, 400);
    assert.equal((await add({ region: 'Only Region' })).status, 400);
    assert.equal((await add({ branchName: ['x'], region: 'Gauteng' })).status, 400);
  });

  it('assigns and clears a coordinator\'s or member\'s branch, but not an admin\'s', async () => {
    const admin = await addUser({ role: 'admin' });
    const { body: { branch } } = await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName: 'East', region: 'Gauteng' } });
    const c = await addUser({ role: 'coordinator' });
    const m = await addUser();
    const other = await addUser({ role: 'admin' });
    const set = (id, ngoBranch) => app.api('PATCH', `/api/admin/users/${id}/branch`, { token: admin.token, body: { ngoBranch } });
    assert.equal((await set(c.user._id, branch._id)).status, 200);
    assert.equal(c.user.ngoBranch, branch._id);
    assert.equal((await set(c.user._id, null)).status, 200);
    assert.equal(c.user.ngoBranch, null);
    assert.equal((await set(m.user._id, branch._id)).status, 200, 'members can be placed in a branch');
    assert.equal(m.user.ngoBranch, branch._id);
    assert.equal((await set(other.user._id, branch._id)).status, 400, 'admins are not tied to a branch');
    assert.equal((await set(c.user._id, 'e'.repeat(24))).status, 400);
    assert.equal((await set(c.user._id, 'nope')).status, 400);
  });
});

describe('resetting someone\'s password', () => {
  it('sets a temporary password and signs them out everywhere', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    const stale = oldToken(m.user, 120);
    const r = await app.api('POST', `/api/admin/users/${m.user._id}/reset-password`, { token: admin.token, body: { newPassword: 'Reset@12345' } });
    assert.equal(r.status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: m.phone, password: 'Reset@12345' } })).status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: m.phone, password: m.password } })).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 401);
  });

  it('rejects weak passwords, bad ids and self-reset', async () => {
    const admin = await addUser({ role: 'admin' });
    const m = await addUser();
    const reset = (id, newPassword) => app.api('POST', `/api/admin/users/${id}/reset-password`, { token: admin.token, body: { newPassword } });
    assert.equal((await reset(m.user._id, 'weak')).status, 400);
    assert.equal((await reset(m.user._id, undefined)).status, 400);
    assert.equal((await reset('nope', 'Reset@12345')).status, 400);
    assert.equal((await reset('e'.repeat(24), 'Reset@12345')).status, 404);
    assert.equal((await reset(admin.user._id, 'Reset@12345')).status, 400);
  });
});
