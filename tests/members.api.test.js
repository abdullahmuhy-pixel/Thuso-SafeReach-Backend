// What a signed-in member can do: check-ins, SOS alerts and incident reports.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

describe('check-ins', () => {
  const start = (token, body) => app.api('POST', '/api/checkin', { token, body });

  it('starts a check-in with the right expiry', async () => {
    const { token } = await addUser();
    const before = Date.now();
    const r = await start(token, { durationMinutes: 15, destination: 'Sandton', lat: '-26.204100', lng: '28.047300' });
    assert.equal(r.status, 201);
    assert.equal(r.body.checkIn.status, 'active');
    const expires = new Date(r.body.checkIn.expiresAt).getTime();
    assert.ok(Math.abs(expires - (before + 15 * 60000)) < 5000);
  });

  it('allows only one active check-in at a time (409)', async () => {
    const { token } = await addUser();
    assert.equal((await start(token, { durationMinutes: 15 })).status, 201);
    assert.equal((await start(token, { durationMinutes: 30 })).status, 409);
  });

  it('GET /active returns the current check-in, or null', async () => {
    const { token } = await addUser();
    assert.equal((await app.api('GET', '/api/checkin/active', { token })).body.checkIn, null);
    await start(token, { durationMinutes: 15 });
    assert.ok((await app.api('GET', '/api/checkin/active', { token })).body.checkIn);
  });

  it('rejects bad durations and coordinates with 400', async () => {
    const { token } = await addUser();
    for (const body of [
      {}, { durationMinutes: 1 }, { durationMinutes: 99999 }, { durationMinutes: 'soon' },
      { durationMinutes: [15] }, { durationMinutes: { a: 1 } },
      { durationMinutes: 15, lat: '-26' }, { durationMinutes: 15, destination: 'bad: colon' },
    ]) {
      assert.equal((await start(token, body)).status, 400, JSON.stringify(body));
    }
  });

  it('extends and ends a check-in', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    const ext = await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 15 } });
    assert.equal(ext.status, 200);
    assert.equal(new Date(ext.body.checkIn.expiresAt) - new Date(checkIn.expiresAt), 15 * 60000);
    const safe = await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal(safe.body.checkIn.status, 'safe');
  });

  it('refuses silly extensions and extending a finished check-in', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    for (const minutes of [-50, 0, 100000, 'abc', [5]]) {
      assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes } })).status, 400, String(minutes));
    }
    await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 15 } })).status, 409);
  });

  it('rejects malformed ids with 400 and other people\'s check-ins with 404', async () => {
    const a = await addUser(), b = await addUser();
    const { body: { checkIn } } = await start(a.token, { durationMinutes: 15 });
    assert.equal((await app.api('PATCH', '/api/checkin/not-an-id/safe', { token: a.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token: b.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token: b.token, body: { minutes: 5 } })).status, 404);
  });
});

describe('SOS alerts', () => {
  const sos = (token, body) => app.api('POST', '/api/sos', { token, body });

  it('creates an active alert and notifies coordinators', async () => {
    const { token } = await addUser();
    const r = await sos(token, { triggerSource: 'manual', lat: '-26.204100', lng: '28.047300' });
    assert.equal(r.status, 201);
    assert.equal(r.body.status, 'active');
    assert.equal(state.alerts.length, 1);
    assert.equal(state.dispatched.length, 1);
    assert.equal(state.dispatched[0]._id, r.body.alertId);
  });

  it('accepts shake and defaults unknown sources to manual', async () => {
    const { token } = await addUser();
    await sos(token, { triggerSource: 'shake' });
    await sos(token, { triggerSource: 'made-up' });
    assert.deepEqual(state.alerts.map(a => a.triggerSource), ['shake', 'manual']);
  });

  it('works with no body at all (location unknown)', async () => {
    const { token } = await addUser();
    assert.equal((await sos(token, {})).status, 201);
  });

  it('rejects bad coordinates and bad check-in ids with 400', async () => {
    const { token } = await addUser();
    for (const body of [{ lat: '-26' }, { lng: 'abc' }, { checkInId: 'nope' }, { checkInId: ['x'] }, { checkInId: { a: 1 } }]) {
      assert.equal((await sos(token, body)).status, 400, JSON.stringify(body));
    }
    assert.equal(state.alerts.length, 0);
  });

  it('is members-only and needs a session', async () => {
    const coord = await addUser({ role: 'coordinator' });
    assert.equal((await sos(coord.token, {})).status, 403);
    assert.equal((await sos(undefined, {})).status, 401);
  });
});

describe('incident reports', () => {
  const report = (token, body) => app.api('POST', '/api/incidents', { token, body });
  const good = { type: 'theft', description: 'A briefcase was stolen', severity: 'high', location: 'Main Rd', lat: '-26.033682', lng: '27.971534' };

  it('creates a report', async () => {
    const { token } = await addUser();
    const r = await report(token, good);
    assert.equal(r.status, 201);
    assert.equal(r.body.incident.severity, 'high');
  });

  it('defaults an unknown severity to medium', async () => {
    const { token } = await addUser();
    assert.equal((await report(token, { ...good, severity: 'extreme' })).body.incident.severity, 'medium');
  });

  it('rejects missing or invalid fields with 400', async () => {
    const { token } = await addUser();
    for (const body of [
      { type: 'theft' }, { description: 'no type' }, { ...good, type: 'alien-invasion' },
      { ...good, description: 'has: a colon' }, { ...good, description: ['x'] }, { ...good, lat: '-26' },
    ]) {
      assert.equal((await report(token, body)).status, 400, JSON.stringify(body));
    }
  });

  it('lists only the member\'s own reports', async () => {
    const a = await addUser(), b = await addUser();
    await report(a.token, good);
    await report(b.token, { ...good, description: 'Someone else report' });
    const mine = await app.api('GET', '/api/incidents/mine', { token: a.token });
    assert.equal(mine.body.length, 1);
    assert.equal(mine.body[0].description, 'A briefcase was stolen');
  });
});

describe('role separation', () => {
  it('keeps members out of the coordinator and admin areas', async () => {
    const { token } = await addUser();
    for (const p of ['/api/coordinator/dashboard', '/api/coordinator/members', '/api/admin/users', '/api/admin/branches']) {
      assert.equal((await app.api('GET', p, { token })).status, 403, p);
    }
  });
});
