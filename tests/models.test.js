// Mongoose model checks that need no database connection: schema rules and
// that secrets can never be serialised. Skipped automatically if mongoose is
// not installed.
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

let mongoose = null;
try { mongoose = require('mongoose'); } catch (e) { /* not installed */ }

describe('User model', { skip: mongoose ? false : 'mongoose is not installed' }, () => {
  const User = mongoose ? require('../models/User') : null;
  const valid = { fullName: 'Jane Doe', phoneNumber: '+27821230001', passwordHash: 'hash' };

  it('applies sensible defaults', () => {
    const u = new User(valid);
    assert.equal(u.role, 'member');
    assert.equal(u.active, true);
    assert.equal(u.totpEnabled, false);
    assert.equal(u.ngoBranch, null);
    assert.equal(u.validateSync(), undefined);
  });

  it('requires the core fields and a known role', () => {
    assert.ok(new User({ ...valid, passwordHash: undefined }).validateSync());
    assert.ok(new User({ ...valid, phoneNumber: undefined }).validateSync());
    assert.ok(new User({ ...valid, role: 'superuser' }).validateSync());
  });

  it('hides the 2FA secrets from normal queries (select: false)', () => {
    for (const field of ['totpSecret', 'totpPendingSecret', 'recoveryHashes']) {
      assert.equal(User.schema.path(field).options.select, false, field);
    }
  });

  it('toSafeJSON never includes the password hash or any 2FA secret', () => {
    const u = new User({ ...valid, role: 'coordinator', totpEnabled: true, totpSecret: 'SECRET', recoveryHashes: ['recovery-hash-value-xyz'] });
    const safe = u.toSafeJSON();
    const text = JSON.stringify(safe);
    for (const leak of ['passwordHash', 'hash', 'totpSecret', 'SECRET', 'recoveryHashes', 'recovery-hash-value-xyz']) {
      assert.ok(!text.includes(leak), 'leaked ' + leak);
    }
    assert.equal(safe.role, 'coordinator');
    assert.equal(safe.twoFactorEnabled, true);
    assert.equal(safe.active, true);
  });
});
