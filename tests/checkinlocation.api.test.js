// Check-in locations: where a check-in started, where the member pressed
// "I'm safe", and the last position the phone reported, which is used as the
// best estimate when a check-in is missed.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');
const { sweepOnce } = require('../services/CheckInSweeper');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

const start = (token, body) => app.api('POST', '/api/checkin', { token, body });
const loc = (token, id, body) => app.api('PATCH', `/api/checkin/${id}/location`, { token, body });

describe('check-in locations', () => {
  it('records the start location and the location where I\'m safe was pressed', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 20, lat: '-22.5609', lng: '17.0658' });
    assert.equal(checkIn.lat, '-22.5609');
    const safe = await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, {
      token, body: { lat: '-22.5701', lng: '17.0832', accuracy: 14.6 },
    });
    assert.equal(safe.status, 200);
    assert.equal(safe.body.checkIn.safeLat, -22.5701);
    assert.equal(safe.body.checkIn.safeLng, 17.0832);
    assert.equal(safe.body.checkIn.lastAccuracy, 15);
  });

  it('pressing I\'m safe without a location still works', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15 });
    const safe = await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token });
    assert.equal(safe.body.checkIn.status, 'safe');
    assert.equal(safe.body.checkIn.safeLat, null);
  });

  it('keeps the latest position and a capped trail while the timer runs', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 30 });
    for (let i = 0; i < 55; i++) {
      const r = await loc(token, checkIn._id, { lat: (-22.5 - i / 1000).toFixed(4), lng: '17.0700', accuracy: 20 });
      assert.equal(r.status, 200);
    }
    const c = state.checkIns[0];
    assert.equal(c.lastLat, -22.554);
    assert.equal(c.locationTrail.length, 50);
    assert.equal(c.locationTrail[49].lat, -22.554);
    assert.ok(c.lastLocationAt);
  });

  it('a missed check-in is escalated with the last known location, not the start', async () => {
    const { token } = await addUser();
    const { body: { checkIn } } = await start(token, { durationMinutes: 15, lat: '-22.5609', lng: '17.0658', destination: 'Katutura' });
    await loc(token, checkIn._id, { lat: '-22.5200', lng: '17.0500', accuracy: 30 });
    state.checkIns[0].expiresAt = new Date(Date.now() - 1000);
    await sweepOnce();
    assert.equal(state.alerts.length, 1);
    assert.equal(state.alerts[0].lat, -22.52);
    assert.equal(state.alerts[0].lng, 17.05);
    assert.match(state.incidents[0].description, /Last known location from 0 min before escalation \(accuracy about 30 m\)/);
  });

  it('a missed check-in with no updates falls back to where it started', async () => {
    const { token } = await addUser();
    await start(token, { durationMinutes: 15, lat: '-22.5609', lng: '17.0658' });
    state.checkIns[0].expiresAt = new Date(Date.now() - 1000);
    await sweepOnce();
    assert.equal(state.alerts[0].lat, '-22.5609');
    assert.match(state.incidents[0].description, /where the check-in was started/);
  });

  it('rejects bad coordinates and updates to finished or other members\' check-ins', async () => {
    const me = await addUser();
    const other = await addUser();
    const { body: { checkIn } } = await start(me.token, { durationMinutes: 15 });
    assert.equal((await loc(me.token, checkIn._id, { lat: 'abc', lng: '17.0' })).status, 400);
    assert.equal((await loc(me.token, checkIn._id, { lat: '95.0', lng: '17.0' })).status, 400);
    assert.equal((await loc(me.token, checkIn._id, {})).status, 400);
    assert.equal((await loc(other.token, checkIn._id, { lat: '-22.5', lng: '17.0' })).status, 404);
    await app.api('PATCH', `/api/checkin/${checkIn._id}/safe`, { token: me.token });
    assert.equal((await loc(me.token, checkIn._id, { lat: '-22.5', lng: '17.0' })).status, 409);
  });
});
