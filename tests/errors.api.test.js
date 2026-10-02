// Robustness: bad input and internal failures must produce clean errors and
// never take the server down.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
const realConsoleError = console.error;
// The server logs unexpected errors (that is the point of these tests), so keep
// that expected noise out of the test report.
before(async () => { console.error = () => {}; app = await startApp(); });
after(async () => { console.error = realConsoleError; await app.close(); });
beforeEach(() => fakes.reset());

describe('basics', () => {
  it('GET /api/health reports ok', async () => {
    const r = await app.api('GET', '/api/health');
    assert.equal(r.status, 200);
    assert.equal(r.body.status, 'ok');
    assert.ok(!Number.isNaN(Date.parse(r.body.time)));
  });

  it('unknown routes get a JSON 404', async () => {
    const r = await app.api('GET', '/api/nope');
    assert.equal(r.status, 404);
    assert.ok(r.body.error);
  });
});

describe('bad requests', () => {
  it('malformed JSON is a 400, not a 500', async () => {
    const r = await app.api('POST', '/api/auth/login', { raw: '{"phoneNumber": ' });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /json/i);
  });

  it('an oversized body is a 413', async () => {
    const r = await app.api('POST', '/api/auth/login', { raw: JSON.stringify({ x: 'a'.repeat(200 * 1024) }) });
    assert.equal(r.status, 413);
  });

  it('non-object JSON bodies are rejected cleanly', async () => {
    for (const raw of ['[]', 'null', '"text"', '123']) {
      for (const p of ['/api/auth/login', '/api/auth/register', '/api/coordinator/auth/login']) {
        const r = await app.api('POST', p, { raw });
        assert.equal(r.status, 400, `${p} <- ${raw}`);
      }
    }
  });

  it('empty bodies are rejected cleanly on every public POST', async () => {
    for (const p of ['/api/auth/login', '/api/auth/register', '/api/coordinator/auth/login', '/api/coordinator/auth/verify-2fa']) {
      assert.equal((await app.api('POST', p, { body: {} })).status, 400, p);
    }
  });
});

describe('internal failures', () => {
  it('an unexpected error becomes a generic 500 with no stack trace or internals', async () => {
    const { phone, password } = await addUser();
    state.failNext.add('UserRepository.findByPhone');
    const r = await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } });
    assert.equal(r.status, 500);
    const text = JSON.stringify(r.body);
    assert.ok(!text.includes('simulated'), 'internal message leaked');
    assert.ok(!/stack|\.js:\d+/i.test(text), 'stack trace leaked');
  });

  it('the server keeps serving after an internal error (async handlers cannot crash it)', async () => {
    const { phone, password } = await addUser();
    state.failNext.add('UserRepository.findByPhone');
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } })).status, 500);
    assert.equal((await app.api('GET', '/api/health')).status, 200);
    assert.equal((await app.api('POST', '/api/auth/login', { body: { phoneNumber: phone, password } })).status, 200);
  });

  it('a failure inside an admin route is also contained', async () => {
    const admin = await addUser({ role: 'admin' });
    state.failNext.add('UserRepository.create');
    const r = await app.api('POST', '/api/admin/users', { token: admin.token, body: { fullName: 'New Person', phoneNumber: '+27820009999', password: 'Coord@1234', role: 'coordinator' } });
    assert.equal(r.status, 500);
    assert.equal((await app.api('GET', '/api/admin/users', { token: admin.token })).status, 200);
  });
});
