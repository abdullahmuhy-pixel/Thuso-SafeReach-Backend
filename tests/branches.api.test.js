// Branch-scoped visibility: a coordinator sees their own branch's alerts,
// incident reports and members — plus anything not yet assigned to a branch —
// while admins and branch-less coordinators see everything.
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { fakes, state, addUser, startApp } = require('./helpers/setup');

let app;
before(async () => { app = await startApp(); });
after(async () => { await app.close(); });
beforeEach(() => fakes.reset());

// Two branches, a coordinator + member in each, plus an unassigned member,
// a branch-less coordinator and an admin.
async function world() {
  const admin = await addUser({ role: 'admin', name: 'Admin' });
  const mk = async (branchName, region) => (await app.api('POST', '/api/admin/branches', { token: admin.token, body: { branchName, region } })).body.branch;
  const north = await mk('Thuso North', 'Gauteng');
  const south = await mk('Thuso South', 'Gauteng');
  const inBranch = async (user, branch) => { user.user.ngoBranch = branch._id; return user; };

  const w = {
    admin, north, south,
    coordN: await inBranch(await addUser({ role: 'coordinator', name: 'Coord North' }), north),
    coordS: await inBranch(await addUser({ role: 'coordinator', name: 'Coord South' }), south),
    coordAll: await addUser({ role: 'coordinator', name: 'Coord No Branch' }),
    memberN: await inBranch(await addUser({ name: 'Member North' }), north),
    memberS: await inBranch(await addUser({ name: 'Member South' }), south),
    memberNone: await addUser({ name: 'Member Unassigned' }),
  };
  return w;
}
const dash = (who) => app.api('GET', '/api/coordinator/dashboard', { token: who.token });
const names = list => list.map(a => a.userId.fullName).sort();

describe('alerts are routed to the member\'s branch', () => {
  it('stores the member\'s branch on the alert and on incident reports', async () => {
    const w = await world();
    const sos = await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    const rep = await app.api('POST', '/api/incidents', { token: w.memberN.token, body: { type: 'theft', description: 'Bag stolen' } });
    assert.equal(state.alerts.find(a => a._id === sos.body.alertId).ngoBranch, w.north._id);
    assert.equal(rep.body.incident.ngoBranch, w.north._id);
    const unassigned = await app.api('POST', '/api/sos', { token: w.memberNone.token, body: {} });
    assert.equal(state.alerts.find(a => a._id === unassigned.body.alertId).ngoBranch, null);
  });
});

describe('who sees which alerts', () => {
  it('branch coordinators see their branch + unassigned members, never another branch', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS, w.memberNone]) await app.api('POST', '/api/sos', { token: m.token, body: {} });

    assert.deepEqual(names((await dash(w.coordN)).body.activeAlerts), ['Member North', 'Member Unassigned']);
    assert.deepEqual(names((await dash(w.coordS)).body.activeAlerts), ['Member South', 'Member Unassigned']);
  });

  it('admins and coordinators without a branch see every alert', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS, w.memberNone]) await app.api('POST', '/api/sos', { token: m.token, body: {} });
    for (const who of [w.admin, w.coordAll]) {
      assert.equal((await dash(who)).body.activeAlerts.length, 3);
    }
  });

  it('the plain alerts list is scoped the same way', async () => {
    const w = await world();
    for (const m of [w.memberN, w.memberS]) await app.api('POST', '/api/sos', { token: m.token, body: {} });
    const list = await app.api('GET', '/api/sos', { token: w.coordN.token });
    assert.equal(list.body.length, 1);
    assert.equal(list.body[0].userId.fullName, 'Member North');
  });

  it('tells the dashboard what the coordinator is looking at', async () => {
    const w = await world();
    const n = (await dash(w.coordN)).body.scope;
    assert.equal(n.all, false);
    assert.equal(n.branch.branchName, 'Thuso North');
    assert.equal((await dash(w.admin)).body.scope.all, true);
    assert.equal((await dash(w.coordAll)).body.scope.branch, null);
  });

  it('an alert keeps its branch even if the member is moved later', async () => {
    const w = await world();
    await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    await app.api('PATCH', `/api/admin/users/${w.memberN.user._id}/branch`, { token: w.admin.token, body: { ngoBranch: w.south._id } });
    assert.equal((await dash(w.coordN)).body.activeAlerts.length, 1, 'North still owns the alert it was sent');
    assert.equal((await dash(w.coordS)).body.activeAlerts.length, 0);
  });
});

describe('resolving and reviewing are scoped too', () => {
  it('a coordinator cannot resolve another branch\'s alert (404, nothing changes)', async () => {
    const w = await world();
    const { body: { alertId } } = await app.api('POST', '/api/sos', { token: w.memberN.token, body: {} });
    const r = await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: w.coordS.token });
    assert.equal(r.status, 404);
    assert.equal(state.alerts.find(a => a._id === alertId).status, 'active');
    assert.equal((await app.api('PATCH', `/api/sos/${alertId}/resolve`, { token: w.coordN.token })).status, 200);
  });

  it('anyone in scope can resolve unassigned alerts, and admins can resolve any', async () => {
    const w = await world();
    const a = (await app.api('POST', '/api/sos', { token: w.memberNone.token, body: {} })).body.alertId;
    const b = (await app.api('POST', '/api/sos', { token: w.memberS.token, body: {} })).body.alertId;
    assert.equal((await app.api('PATCH', `/api/sos/${a}/resolve`, { token: w.coordN.token })).status, 200);
    assert.equal((await app.api('PATCH', `/api/sos/${b}/resolve`, { token: w.admin.token })).status, 200);
  });

  it('incident reports: scoped list, and review is limited to your scope', async () => {
    const w = await world();
    const rN = (await app.api('POST', '/api/incidents', { token: w.memberN.token, body: { type: 'fire', description: 'North fire' } })).body.incident;
    await app.api('POST', '/api/incidents', { token: w.memberS.token, body: { type: 'fire', description: 'South fire' } });

    const mine = await dash(w.coordN);
    assert.deepEqual(mine.body.recentIncidents.map(i => i.description), ['North fire']);
    assert.equal((await app.api('GET', '/api/incidents', { token: w.coordS.token })).body.length, 1);
    assert.equal((await app.api('GET', '/api/incidents', { token: w.admin.token })).body.length, 2);

    assert.equal((await app.api('PATCH', `/api/incidents/${rN._id}/review`, { token: w.coordS.token })).status, 404);
    assert.equal((await app.api('PATCH', `/api/incidents/${rN._id}/review`, { token: w.coordN.token })).status, 200);
  });
});

describe('member records', () => {
  it('a branch coordinator sees their branch\'s members + unassigned ones only', async () => {
    const w = await world();
    const r = await app.api('GET', '/api/coordinator/members', { token: w.coordN.token });
    assert.deepEqual(r.body.map(m => m.fullName).sort(), ['Member North', 'Member Unassigned']);
    assert.equal((await app.api('GET', '/api/coordinator/members', { token: w.admin.token })).body.length, 3);
    assert.equal((await app.api('GET', '/api/coordinator/members', { token: w.coordAll.token })).body.length, 3);
  });
});

describe('missed check-ins are routed by branch as well', () => {
  const sweeper = require('../services/CheckInSweeper');
  const origLog = console.log;
  before(() => { console.log = () => {}; });
  after(() => { console.log = origLog; });

  it('the escalated alert and incident carry the member\'s branch', async () => {
    const w = await world();
    state.checkIns.push({ _id: 'c'.repeat(24), userId: w.memberS.user._id, status: 'active', durationMinutes: 5, destination: 'Soweto', lat: null, lng: null, expiresAt: new Date(Date.now() - 60000) });
    await sweeper.sweepOnce();
    assert.equal(state.alerts[0].ngoBranch, w.south._id);
    assert.equal(state.incidents[0].ngoBranch, w.south._id);
    assert.equal((await dash(w.coordS)).body.activeAlerts.length, 1);
    assert.equal((await dash(w.coordN)).body.activeAlerts.length, 0);
  });
});
