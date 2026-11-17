// Check-in records: every timer a member uses is kept and shown to coordinators,
// not only the ones that time out and raise an SOS alert.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');
const { sweepOnce } = require('../services/CheckInSweeper');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const start = (token, body) => app.api('POST', '/api/checkin', { token, body });

describe('check-in records', () => {
  it('records the safe time, extensions and branch of a check-in', async () => {
    const { token, user } = await addUser({ name: 'Lerato Molefe' });
    const { body: { checkIn } } = await start(token, { durationMinutes: 20, destination: 'Braamfontein' });
    await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 10 } });
    await app.api('PATCH', `/api/checkin/${checkIn._id}/extend`, { token, body: { minutes: 5 } });
    const safe = await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal(safe.body.checkIn.status, 'safe');
    assert.ok(safe.body.checkIn.safeAt);
    assert.equal(safe.body.checkIn.extendedMinutes, 15);
    assert.equal(safe.body.checkIn.extensionCount, 2);
    assert.equal(state.checkIns[0].ngoBranch, user.ngoBranch || null);
  });

  it('pressing I\'m safe twice keeps the first safe time', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    const first = (await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token })).body.checkIn.safeAt;
    const second = (await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token })).body.checkIn.safeAt;
    assert.equal(String(first), String(second));
  });

  it('coordinators see safe, active and escalated check-ins on the dashboard', async () => {
    const a = await addUser({ name: 'Safe Member' });
    const b = await addUser({ name: 'Active Member' });
    const c = await addUser({ name: 'Late Member' });
    const coord = await addUser({ role: 'coordinator' });
    const ca = (await start(a.token, { durationMinutes: 15 })).body.checkIn;
    await app.api('PATCH', `/api/checkin/${ca._id}/safe`, { token: a.token });
    await start(b.token, { durationMinutes: 15 });
    await start(c.token, { durationMinutes: 15 });
    state.checkIns[2].expiresAt = new Date(Date.now() - 1000);
    await sweepOnce();

    const d = await app.api('GET', '/api/coordinator/dashboard', { token: coord.token });
    assert.equal(d.status, 200);
    const byName = Object.fromEntries(d.body.recentCheckIns.map(x => [x.userId.fullName, x.status]));
    assert.deepEqual(byName, { 'Safe Member': 'safe', 'Active Member': 'active', 'Late Member': 'escalated' });

    const all = await app.api('GET', '/api/coordinator/checkins', { token: coord.token });
    assert.equal(all.body.checkIns.length, 3);
    const safeOnly = await app.api('GET', '/api/coordinator/checkins?status=safe', { token: coord.token });
    assert.deepEqual(safeOnly.body.checkIns.map(x => x.userId.fullName), ['Safe Member']);
    assert.ok(safeOnly.body.checkIns[0].safeAt);
  });

  it('members cannot read the coordinator check-in log', async () => {
    const { token } = await addUser();
    assert.equal((await app.api('GET', '/api/coordinator/checkins', { token })).status, 403);
  });

  it('a member can read their own check-in history', async () => {
    const me = await addUser();
    const other = await addUser();
    const c1 = (await start(me.token, { durationMinutes: 15, destination: 'Campus' })).body.checkIn;
    await app.api('PATCH', `/api/checkin/${c1._id}/safe`, { token: me.token });
    await start(me.token, { durationMinutes: 30, destination: 'Home' });
    await start(other.token, { durationMinutes: 15 });
    const h = await app.api('GET', '/api/checkin/history', { token: me.token });
    assert.equal(h.status, 200);
    assert.deepEqual(h.body.checkIns.map(x => x.destination), ['Home', 'Campus']);
  });
});
