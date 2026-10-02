// Two-factor authentication for coordinators and admins, end to end over HTTP.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { fakes, AuthService, TotpService, addUser, oldToken, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const base = '/api/coordinator/auth';
// A 6-digit code that is guaranteed NOT to be valid right now (not even for the
// neighbouring time steps), so these tests can never pass or fail by chance.
const invalidFor = secret => {
  const valid = new Set([-1, 0, 1].map(d => TotpService.codeAt(secret, Date.now() + d * 30000)));
  for (let n = 0; ; n++) { const c = String(n).padStart(6, '0'); if (!valid.has(c)) return c; }
};
const login = (phone, password) => app.api('POST', `${base}/login`, { body: { phoneNumber: phone, password } });
const verify = (challengeToken, code) => app.api('POST', `${base}/verify-2fa`, { body: { challengeToken, code } });
// "Time passes": let the next code be accepted (each 30-second code works once).
const nextStep = user => { user.totpLastStep = (user.totpLastStep || 0) - 5; };

// Turns 2FA on for a fresh account through the real endpoints.
async function enrolled(role = 'coordinator') {
  const acct = await addUser({ role });
  const setup = await app.api('POST', `${base}/2fa/setup`, { token: acct.token, body: { password: acct.password } });
  const secret = setup.body.secret;
  const enable = await app.api('POST', `${base}/2fa/enable`, { token: acct.token, body: { code: TotpService.codeAt(secret) } });
  nextStep(acct.user);
  return { ...acct, secret, recoveryCodes: enable.body.recoveryCodes };
}

describe('logging in without 2FA', () => {
  it('still gives a session straight away', async () => {
    const c = await addUser({ role: 'coordinator' });
    const r = await login(c.phone, c.password);
    assert.equal(r.status, 200);
    assert.ok(r.body.token);
    assert.equal(r.body.requires2FA, undefined);
    assert.equal(r.body.user.twoFactorEnabled, false);
  });
});

describe('turning 2FA on', () => {
  it('needs the account password', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: 'Wrong@1234' } })).status, 400);
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: {} })).status, 400);
  });

  it('is for coordinators and admins only', async () => {
    const m = await addUser();
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: m.token, body: { password: m.password } })).status, 403);
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { body: { password: 'x' } })).status, 401);
  });

  it('returns a secret and an authenticator link, and stores the secret encrypted', async () => {
    const c = await addUser({ role: 'coordinator' });
    const r = await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } });
    assert.equal(r.status, 200);
    assert.match(r.body.secret, /^[A-Z2-7]{32}$/);
    assert.ok(r.body.otpauthUrl.startsWith('otpauth://totp/'));
    assert.notEqual(c.user.totpPendingSecret, r.body.secret);
    assert.equal(TotpService.decrypt(c.user.totpPendingSecret), r.body.secret);
    assert.equal(c.user.totpEnabled, false, 'not on until a code is confirmed');
  });

  it('switches on only after a correct first code, then returns 8 one-time recovery codes', async () => {
    const c = await addUser({ role: 'admin' });
    const { body: { secret } } = await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } });
    const bad = await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: invalidFor(secret) } });
    assert.equal(bad.status, 400);
    assert.equal(c.user.totpEnabled, false);
    assert.equal((await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: {} })).status, 400);

    const ok = await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: TotpService.codeAt(secret) } });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.recoveryCodes.length, 8);
    assert.equal(c.user.totpEnabled, true);
    assert.equal(c.user.recoveryHashes.length, 8);
    assert.ok(!c.user.recoveryHashes.some(h => ok.body.recoveryCodes.map(x => x.replace('-', '')).includes(h)), 'only hashes are stored');
  });

  it('cannot be started again while it is on (409)', async () => {
    const c = await enrolled();
    assert.equal((await app.api('POST', `${base}/2fa/setup`, { token: c.token, body: { password: c.password } })).status, 409);
  });

  it('cannot be enabled without starting setup first', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/enable`, { token: c.token, body: { code: '123456' } })).status, 400);
  });
});

describe('the two-step login', () => {
  it('gives no session after the password alone, only a challenge', async () => {
    const c = await enrolled();
    const r = await login(c.phone, c.password);
    assert.equal(r.status, 200);
    assert.equal(r.body.requires2FA, true);
    assert.ok(r.body.challengeToken);
    assert.ok(!r.body.token);
  });

  it('a wrong password never produces a challenge', async () => {
    const c = await enrolled();
    const r = await login(c.phone, 'Wrong@1234');
    assert.equal(r.status, 401);
    assert.ok(!r.body.challengeToken);
  });

  it('a correct code completes the sign-in and the session works', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const r = await verify(challengeToken, TotpService.codeAt(c.secret));
    assert.equal(r.status, 200);
    assert.equal(r.body.user.twoFactorEnabled, true);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: r.body.token })).status, 200);
  });

  it('a wrong code is refused, and a code cannot be used twice (replay)', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 401);
    assert.equal((await verify(challengeToken, code)).status, 200);
    assert.equal((await verify(challengeToken, code)).status, 401, 'same code again');
  });

  it('accepts a code typed with a space', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify(challengeToken, code.slice(0, 3) + ' ' + code.slice(3))).status, 200);
  });

  it('the challenge cannot be used as a session, and a session cannot be used as a challenge', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: challengeToken })).status, 401);
    assert.equal((await verify(c.token, TotpService.codeAt(c.secret))).status, 401);
  });

  it('rejects garbage, expired and wrong-purpose challenges', async () => {
    const c = await enrolled();
    const secret = process.env.JWT_SECRET + ':2fa-challenge';
    const code = TotpService.codeAt(c.secret);
    assert.equal((await verify('garbage', code)).status, 401);
    const expired = jwt.sign({ id: c.user._id, purpose: '2fa', iat: Math.floor(Date.now() / 1000) - 3600 }, secret, { expiresIn: '5m' });
    assert.equal((await verify(expired, code)).status, 401);
    const wrongPurpose = jwt.sign({ id: c.user._id, purpose: 'other' }, secret, { expiresIn: '5m' });
    assert.equal((await verify(wrongPurpose, code)).status, 401);
  });

  it('rejects missing and non-string input with 400', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    assert.equal((await app.api('POST', `${base}/verify-2fa`, { body: { challengeToken } })).status, 400);
    assert.equal((await app.api('POST', `${base}/verify-2fa`, { body: { code: '123456' } })).status, 400);
    assert.equal((await verify(challengeToken, ['123456'])).status, 400);
    assert.equal((await verify(challengeToken, 'x'.repeat(100))).status, 400);
  });

  it('refuses a challenge for an account deactivated in the meantime', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    c.user.active = false;
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 401);
  });

  it('works the same for admins', async () => {
    const a = await enrolled('admin');
    assert.equal((await login(a.phone, a.password)).body.requires2FA, true);
  });
});

describe('the member login cannot be used to skip 2FA', () => {
  it('refuses a coordinator or admin who has 2FA on', async () => {
    for (const role of ['coordinator', 'admin']) {
      const acct = await enrolled(role);
      const r = await app.api('POST', '/api/auth/login', { body: { phoneNumber: acct.phone, password: acct.password } });
      assert.equal(r.status, 401);
      assert.ok(!r.body.token);
    }
  });
});

describe('recovery codes', () => {
  it('sign you in once each, in any letter case', async () => {
    const c = await enrolled();
    const use = async code => verify((await login(c.phone, c.password)).body.challengeToken, code);
    assert.equal((await use(c.recoveryCodes[0])).status, 200);
    assert.equal((await use(c.recoveryCodes[0])).status, 401, 'second use refused');
    assert.equal((await use(c.recoveryCodes[1].toUpperCase())).status, 200);
    assert.equal(c.user.recoveryHashes.length, 6);
  });
});

describe('brute-force protection', () => {
  it('locks the account after 5 wrong codes, even for the right code, until the lock expires', async () => {
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    for (let i = 0; i < 4; i++) assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 401);
    assert.equal((await verify(challengeToken, invalidFor(c.secret))).status, 429, 'fifth wrong code locks');
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 429, 'right code refused while locked');
    c.user.totpLockedUntil = new Date(Date.now() - 1000);
    assert.equal((await verify(challengeToken, TotpService.codeAt(c.secret))).status, 200, 'works once the lock ends');
  });
});

describe('turning 2FA off', () => {
  it('needs the password and a valid code', async () => {
    const c = await enrolled();
    const off = body => app.api('POST', `${base}/2fa/disable`, { token: c.token, body });
    assert.equal((await off({ password: 'Wrong@1234', code: TotpService.codeAt(c.secret) })).status, 400);
    assert.equal((await off({ password: c.password, code: invalidFor(c.secret) })).status, 400);
    assert.equal((await off({ password: c.password })).status, 400);
    assert.equal(c.user.totpEnabled, true, 'still on after every failed attempt');
    assert.equal((await off({ password: c.password, code: TotpService.codeAt(c.secret) })).status, 200);
    assert.equal(c.user.totpEnabled, false);
    assert.equal(c.user.totpSecret, null);
    assert.equal(c.user.recoveryHashes.length, 0);
  });

  it('returns sign-in to a single step', async () => {
    const c = await enrolled();
    await app.api('POST', `${base}/2fa/disable`, { token: c.token, body: { password: c.password, code: c.recoveryCodes[0] } });
    const r = await login(c.phone, c.password);
    assert.ok(r.body.token);
    assert.ok(!r.body.requires2FA);
  });

  it('refuses when 2FA is not on', async () => {
    const c = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('POST', `${base}/2fa/disable`, { token: c.token, body: { password: c.password, code: '123456' } })).status, 400);
  });
});

describe('admin reset of a lost authenticator', () => {
  it('switches 2FA off for that account and signs them out', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    const stale = oldToken(c.user, 120);
    const r = await app.api('POST', `/api/admin/users/${c.user._id}/reset-2fa`, { token: admin.token });
    assert.equal(r.status, 200);
    assert.equal(c.user.totpEnabled, false);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: stale })).status, 401);
    assert.ok((await login(c.phone, c.password)).body.token, 'can sign in with just the password again');
  });

  it('is admin-only, cannot target yourself, and validates the id', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    assert.equal((await app.api('POST', `/api/admin/users/${c.user._id}/reset-2fa`, { token: c.token })).status, 403);
    assert.equal((await app.api('POST', `/api/admin/users/${admin.user._id}/reset-2fa`, { token: admin.token })).status, 400);
    assert.equal((await app.api('POST', '/api/admin/users/nope/reset-2fa', { token: admin.token })).status, 400);
    assert.equal((await app.api('POST', `/api/admin/users/${'e'.repeat(24)}/reset-2fa`, { token: admin.token })).status, 404);
  });
});

describe('what the API never reveals', () => {
  it('login, verify and list responses contain no secrets', async () => {
    const admin = await addUser({ role: 'admin' });
    const c = await enrolled();
    const { body: { challengeToken } } = await login(c.phone, c.password);
    const v = await verify(challengeToken, TotpService.codeAt(c.secret));
    const list = await app.api('GET', '/api/admin/users', { token: admin.token });
    const text = JSON.stringify([v.body.user, list.body]);
    for (const leak of ['passwordHash', 'totpSecret', 'totpPendingSecret', 'recoveryHashes', c.secret]) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
  });
});
