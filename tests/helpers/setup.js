// tests/helpers/setup.js — require this FIRST in every API test file.
// Sets the environment, swaps in the fakes, then loads the REAL server.js
// (the actual middleware stack, routes and error handler).
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-only-secret-not-used-anywhere-else';
process.env.JWT_EXPIRES_IN = '1h';
process.env.BCRYPT_ROUNDS = '4'; // fast hashing for tests; production uses 12
delete process.env.CORS_ORIGIN;

const fakes = require('./fakes');
fakes.installAll();

const jwt = require('jsonwebtoken');
const AuthService = require('../../services/AuthService');
const TotpService = require('../../services/TotpService');

let phoneSeq = 1;
const nextPhone = () => '+2782000' + String(phoneSeq++).padStart(4, '0');

async function addUser({ role = 'member', password = 'Passw0rd!', name = 'Test Person', phone } = {}) {
  const user = await fakes.UserRepository.create({
    fullName: name, phoneNumber: phone || nextPhone(), role,
    passwordHash: await AuthService.hashPassword(password),
  });
  return { user, password, phone: user.phoneNumber, token: AuthService.issueToken(user) };
}

// A session token issued `secondsAgo` seconds in the past (to prove that
// sessions older than a password change/reset are revoked).
function oldToken(user, secondsAgo = 120) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role, iat: Math.floor(Date.now() / 1000) - secondsAgo },
    process.env.JWT_SECRET, { expiresIn: '1h' });
}

async function startApp() {
  const app = require('../../server');
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function api(method, urlPath, { token, body, raw } = {}) {
    const headers = {};
    if (token) headers.Authorization = 'Bearer ' + token;
    let payload;
    if (raw !== undefined) { payload = raw; headers['Content-Type'] = 'application/json'; }
    else if (body !== undefined) { payload = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    const res = await fetch(base + urlPath, { method, headers, body: payload });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON body */ }
    return { status: res.status, body: data };
  }
  const close = () => new Promise(resolve => {
    if (server.closeAllConnections) server.closeAllConnections();
    server.close(() => resolve());
  });
  return { api, close };
}

module.exports = { fakes, state: fakes.state, AuthService, TotpService, addUser, oldToken, startApp };
