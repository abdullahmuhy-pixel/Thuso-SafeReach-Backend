// Unit tests for the whitelist validators (middleware/validators.js).
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { isValid, validateBody, validateParams } = require('../middleware/validators');

// Minimal stand-ins for Express's req/res so the middleware can run on its own.
function run(mw, req) {
  const out = { status: null, body: null, nexted: false };
  const res = { status(c) { out.status = c; return res; }, json(b) { out.body = b; return res; } };
  mw(req, res, () => { out.nexted = true; });
  return out;
}

describe('isValid', () => {
  it('accepts well-formed values', () => {
    assert.ok(isValid('fullName', "Thabo O'Neil-Smith"));
    assert.ok(isValid('phoneNumber', '+27821234567'));
    assert.ok(isValid('password', 'Test@1234'));
    assert.ok(isValid('latLng', '-26.204100'));
    assert.ok(isValid('latLng', -26.2041));
    assert.ok(isValid('mongoId', 'a'.repeat(24)));
    assert.ok(isValid('branchName', 'Thuso Soweto (North)'));
  });

  it('rejects malformed values', () => {
    assert.ok(!isValid('fullName', 'J4ne'));
    assert.ok(!isValid('fullName', '<script>'));
    assert.ok(!isValid('phoneNumber', '12'));
    assert.ok(!isValid('phoneNumber', '+27 82 123'));
    assert.ok(!isValid('latLng', '-26'), 'needs a decimal point');
    assert.ok(!isValid('latLng', '1.12345678901'), 'max 10 decimals');
    assert.ok(!isValid('mongoId', 'not-an-id'));
    assert.ok(!isValid('description', 'bad: colon'), 'colon is not whitelisted');
  });

  it('enforces the password rules', () => {
    assert.ok(!isValid('password', 'Sh0rt!'), 'too short');
    assert.ok(!isValid('password', 'alllowercase1!'), 'needs a capital');
    assert.ok(!isValid('password', 'NoNumber!!'), 'needs a digit');
    assert.ok(!isValid('password', 'NoSymbol123'), 'needs a symbol');
    assert.ok(!isValid('password', 'Aa1@' + 'x'.repeat(70)), 'over 72 characters');
  });

  it('rejects null, undefined, arrays and objects outright', () => {
    for (const bad of [null, undefined, ['+27821234567'], { a: 1 }, true]) {
      assert.ok(!isValid('phoneNumber', bad), String(JSON.stringify(bad)));
    }
  });
});

describe('validateBody', () => {
  const mw = validateBody({ fullName: 'fullName', phoneNumber: 'phoneNumber' }, ['fullName', 'phoneNumber']);

  it('passes a valid body through', () => {
    const r = run(mw, { body: { fullName: 'Jane Doe', phoneNumber: '+27821234567' } });
    assert.equal(r.nexted, true);
  });

  it('returns 400 for a missing required field', () => {
    const r = run(mw, { body: { fullName: 'Jane Doe' } });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /phoneNumber/);
  });

  it('treats null and empty string as missing', () => {
    assert.equal(run(mw, { body: { fullName: 'Jane Doe', phoneNumber: null } }).status, 400);
    assert.equal(run(mw, { body: { fullName: '', phoneNumber: '+27821234567' } }).status, 400);
  });

  it('returns 400 for an invalid field', () => {
    const r = run(mw, { body: { fullName: 'J4ne', phoneNumber: '+27821234567' } });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /fullName/);
  });

  it('rejects a body that is not a JSON object', () => {
    assert.equal(run(mw, { body: undefined }).status, 400);
    assert.equal(run(mw, { body: [] }).status, 400);
    assert.equal(run(mw, { body: 'text' }).status, 400);
  });

  it('skips optional fields that are absent but validates them when present', () => {
    const optional = validateBody({ destination: 'destination' });
    assert.equal(run(optional, { body: {} }).nexted, true);
    assert.equal(run(optional, { body: { destination: 'Sandton' } }).nexted, true);
    assert.equal(run(optional, { body: { destination: 'bad: colon' } }).status, 400);
  });
});

describe('validateParams', () => {
  const mw = validateParams({ id: 'mongoId' });
  it('accepts a valid id', () => assert.equal(run(mw, { params: { id: 'a'.repeat(24) } }).nexted, true));
  it('rejects an invalid id with 400', () => assert.equal(run(mw, { params: { id: 'nope' } }).status, 400));
});
