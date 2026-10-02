// Member registration, login, password change and session handling — over real HTTP.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const register = body => app.api('POST', '/api/auth/register', { body });
const login = (phoneNumber, password) => app.api('POST', '/api/auth/login', { body: { phoneNumber, password } });

describe('POST /api/auth/register', () => {
  const good = { fullName: 'Jane Doe', phoneNumber: '+27821230001', password: 'Passw0rd!' };

  it('creates a member and returns a token, never the password hash', async () => {
    const r = await register(good);
    assert.equal(r.status, 201);
    assert.ok(r.body.token);
    assert.equal(r.body.user.role, 'member');
    assert.ok(!JSON.stringify(r.body).includes('passwordHash'));
    assert.ok(!JSON.stringify(r.body).includes('Passw0rd!'));
  });

  it('stores a bcrypt hash (using the configured cost), never the plain password', async () => {
    await register(good);
    const stored = fakes.state.users[0].passwordHash;
    assert.match(stored, /^\$2[aby]\$04\$[./A-Za-z0-9]{53}$/); // 04 = BCRYPT_ROUNDS set by the test setup
    assert.ok(!stored.includes(good.password));
  });

  it('rejects a duplicate phone number with 409', async () => {
    await register(good);
    assert.equal((await register(good)).status, 409);
  });

  it('rejects weak passwords, bad names and bad numbers with 400', async () => {
    assert.equal((await register({ ...good, password: 'weak' })).status, 400);
    assert.equal((await register({ ...good, fullName: 'J4ne' })).status, 400);
    assert.equal((await register({ ...good, phoneNumber: '12' })).status, 400);
  });

  it('rejects a missing password with 400 instead of crashing', async () => {
    const r = await register({ fullName: 'Jane Doe', phoneNumber: '+27821230002' });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /password/);
  });

  it('rejects array / object values with 400', async () => {
    assert.equal((await register({ ...good, phoneNumber: ['+27821230003'] })).status, 400);
    assert.equal((await register({ ...good, fullName: { $ne: 1 } })).status, 400);
  });
});

describe('POST /api/auth/login', () => {
  it('signs a member in', async () => {
    const { phone, password } = await addUser();
    const r = await login(phone, password);
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
  });

  it('gives the same 401 for a wrong password and an unknown number', async () => {
    const { phone } = await addUser();
    const wrong = await login(phone, 'Wrong@1234');
    const unknown = await login('+27829999999', 'Passw0rd!');
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.deepEqual(wrong.body, unknown.body);
  });

  it('rejects non-string passwords with 400', async () => {
    const { phone } = await addUser();
    assert.equal((await login(phone, { $ne: 1 })).status, 400);
    assert.equal((await login(phone, 12345678)).status, 400);
    assert.equal((await login(phone, undefined)).status, 400);
  });

  it('does not let coordinators or admins in through the member login', async () => {
    const coord = await addUser({ role: 'coordinator' });
    const admin = await addUser({ role: 'admin' });
    for (const u of [coord, admin]) {
      const r = await login(u.phone, u.password);
      assert.equal(r.status, 401);
      assert.ok(!r.body.token);
    }
  });

  it('says a deactivated account is deactivated only after the right password', async () => {
    const { user, phone, password } = await addUser();
    user.active = false;
    assert.equal((await login(phone, password)).status, 403);
    assert.equal((await login(phone, 'Wrong@1234')).status, 401);
  });
});

describe('session handling', () => {
  it('rejects requests with no token, a garbage token, or a deleted user', async () => {
    assert.equal((await app.api('GET', '/api/checkin/active')).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: 'garbage' })).status, 401);
    const { token } = await addUser();
    fakes.state.users.length = 0;
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 401);
  });

  it('stops honouring the token of a deactivated account', async () => {
    const { user, token } = await addUser();
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 200);
    user.active = false;
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).status, 401);
  });

  it('rejects a token signed with a different secret', async () => {
    const jwt = require('jsonwebtoken');
    const { user } = await addUser();
    const forged = jwt.sign({ id: user._id, role: 'member' }, 'some-other-secret', { expiresIn: '1h' });
    assert.equal((await app.api('GET', '/api/checkin/active', { token: forged })).status, 401);
  });
});

describe('PATCH /api/auth/password', () => {
  const change = (token, currentPassword, newPassword) =>
    app.api('PATCH', '/api/auth/password', { token, body: { currentPassword, newPassword } });

  it('changes the password and returns a fresh token', async () => {
    const { phone, password, token } = await addUser();
    const r = await change(token, password, 'NewPass@999');
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
    assert.equal((await login(phone, password)).status, 401, 'old password no longer works');
    assert.equal((await login(phone, 'NewPass@999')).status, 200, 'new password works');
  });

  it('signs out sessions issued before the change but keeps the new one', async () => {
    const { user, password, token } = await addUser();
    const stale = oldToken(user, 120);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 200);
    const r = await change(token, password, 'NewPass@999');
    assert.equal((await app.api('GET', '/api/checkin/active', { token: stale })).status, 401);
    assert.equal((await app.api('GET', '/api/checkin/active', { token: r.body.token })).status, 200);
  });

  it('answers 400 (not 401) for a wrong current password so clients do not log out', async () => {
    const { token } = await addUser();
    assert.equal((await change(token, 'Wrong@1234', 'NewPass@999')).status, 400);
  });

  it('rejects an unchanged, weak, missing or non-string new password', async () => {
    const { password, token } = await addUser();
    assert.equal((await change(token, password, password)).status, 400);
    assert.equal((await change(token, password, 'weak')).status, 400);
    assert.equal((await app.api('PATCH', '/api/auth/password', { token, body: { currentPassword: password } })).status, 400);
    assert.equal((await change(token, ['x'], 'NewPass@999')).status, 400);
  });

  it('needs a signed-in user', async () => {
    const r = await app.api('PATCH', '/api/auth/password', { body: { currentPassword: 'a', newPassword: 'NewPass@999' } });
    assert.equal(r.status, 401);
  });
});
