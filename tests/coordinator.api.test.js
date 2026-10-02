// The coordinator dashboard: live alerts, incident review, members, and the
// server-side check-in sweeper that escalates missed check-ins.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

describe('coordinator dashboard', () => {
  it('shows active alerts with the member\'s name and number, plus recent incidents', async () => {
    const member = await addUser({ name: 'Test User' });
    const coord = await addUser({ role: 'coordinator' });
    await app.api('POST', '/api/sos', { token: member.token, body: { lat: '-26.204100', lng: '28.047300' } });
    await app.api('POST', '/api/incidents', { token: member.token, body: { type: 'theft', description: 'Bag stolen' } });

    const r = await app.api('GET', '/api/coordinator/dashboard', { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.activeAlerts.length, 1);
    assert.equal(r.body.activeAlerts[0].userId.fullName, 'Test User');
    assert.equal(r.body.activeAlerts[0].userId.phoneNumber, member.phone);
    assert.equal(r.body.recentIncidents.length, 1);
  });

  it('is open to admins and closed to everyone signed out', async () => {
    const admin = await addUser({ role: 'admin' });
    assert.equal((await app.api('GET', '/api/coordinator/dashboard', { token: admin.token })).status, 200);
    assert.equal((await app.api('GET', '/api/coordinator/dashboard')).status, 401);
  });

  it('lists members only (not coordinators or admins) and never their password hashes', async () => {
    await addUser({ name: 'Member One' });
    await addUser({ role: 'admin' });
    const coord = await addUser({ role: 'coordinator' });
    const r = await app.api('GET', '/api/coordinator/members', { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.length, 1);
    assert.equal(r.body[0].fullName, 'Member One');
    assert.ok(!JSON.stringify(r.body).includes('passwordHash'));
  });
});

describe('resolving alerts and reviewing incidents', () => {
  it('a coordinator can resolve an alert, and it leaves the active list', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    const { body: { alertId } } = await app.api('POST', '/api/sos', { token: member.token, body: {} });

    const r = await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.alert.status, 'resolved');
    assert.equal(r.body.alert.resolvedBy, coord.user._id);
    const dash = await app.api('GET', '/api/coordinator/dashboard', { token: coord.token });
    assert.equal(dash.body.activeAlerts.length, 0);
  });

  it('rejects bad ids (400), unknown ids (404) and members (403)', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    assert.equal((await app.api('PATCH', '/api/sos/zzz/resolve', { token: coord.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/sos/${'f'.repeat(24)}/resolve`, { token: coord.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/sos/${'f'.repeat(24)}/resolve`, { token: member.token })).status, 403);
  });

  it('a coordinator can mark an incident reviewed', async () => {
    const member = await addUser();
    const coord = await addUser({ role: 'coordinator' });
    const { body: { incident } } = await app.api('POST', '/api/incidents', { token: member.token, body: { type: 'fire', description: 'Shack fire' } });
    const r = await app.api('PATCH', `/api/incidents/${incident._id}/review`, { token: coord.token });
    assert.equal(r.status, 200);
    assert.equal(r.body.incident.reviewedBy, coord.user._id);
    assert.equal((await app.api('PATCH', '/api/incidents/bad/review', { token: coord.token })).status, 400);
    assert.equal((await app.api('PATCH', `/api/incidents/${'f'.repeat(24)}/review`, { token: coord.token })).status, 404);
  });
});

describe('CheckInSweeper', () => {
  const sweeper = require('../services/CheckInSweeper');
  const origLog = console.log;
  before(() => { console.log = () => {}; });
  after(() => { console.log = origLog; });

  it('escalates an expired, unconfirmed check-in into an alert and a high-severity incident', async () => {
    const member = await addUser();
    await fakes.state.checkIns.push({ _id: 'c'.repeat(24), userId: member.user._id, status: 'active', durationMinutes: 5, destination: 'Sandton', lat: null, lng: null, expiresAt: new Date(Date.now() - 60000) });

    await sweeper.sweepOnce();

    assert.equal(state.checkIns[0].status, 'escalated');
    assert.equal(state.alerts.length, 1);
    assert.equal(state.alerts[0].triggerSource, 'checkin_timeout');
    assert.equal(state.incidents.length, 1);
    assert.equal(state.incidents[0].severity, 'high');
    assert.match(state.incidents[0].description, /Sandton/);
    assert.equal(state.dispatched.length, 1);
  });

  it('leaves check-ins alone that are confirmed safe or not yet due, and does not escalate twice', async () => {
    const member = await addUser();
    const base = { userId: member.user._id, durationMinutes: 5, destination: 'x', lat: null, lng: null };
    state.checkIns.push({ ...base, _id: 'a'.repeat(24), status: 'safe', expiresAt: new Date(Date.now() - 60000) });
    state.checkIns.push({ ...base, _id: 'b'.repeat(24), status: 'active', expiresAt: new Date(Date.now() + 600000) });
    state.checkIns.push({ ...base, _id: 'd'.repeat(24), status: 'active', expiresAt: new Date(Date.now() - 1000) });

    await sweeper.sweepOnce();
    await sweeper.sweepOnce();

    assert.equal(state.alerts.length, 1, 'only the one overdue check-in escalates, once');
    assert.equal(state.checkIns.find(c => c._id === 'a'.repeat(24)).status, 'safe');
    assert.equal(state.checkIns.find(c => c._id === 'b'.repeat(24)).status, 'active');
  });
});
