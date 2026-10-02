// Unit tests for the 2FA building blocks (services/TotpService.js), checked
// against the official RFC 4226 / RFC 6238 test vectors.
process.env.JWT_SECRET = 'test-only-secret-not-used-anywhere-else';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Totp = require('../services/TotpService');
const { base32Encode, base32Decode, hotp } = Totp._internals;

// The RFC test secret is the ASCII string "12345678901234567890".
const RFC_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('base32', () => {
  it('encodes the RFC test secret', () => {
    assert.equal(base32Encode(Buffer.from('12345678901234567890')), RFC_SECRET_B32);
  });
  it('round-trips random secrets', () => {
    for (let i = 0; i < 20; i++) {
      const s = Totp.generateSecret();
      assert.equal(s.length, 32);
      assert.match(s, /^[A-Z2-7]+$/);
      assert.equal(base32Encode(base32Decode(s)), s);
    }
  });
  it('rejects characters outside the alphabet', () => {
    assert.throws(() => base32Decode('NOT-VALID-1'));
  });
});

describe('HOTP / TOTP vectors', () => {
  it('RFC 4226 HOTP, counter 0', () => {
    assert.equal(hotp(Buffer.from('12345678901234567890'), 0), '755224');
  });
  it('RFC 6238 at T=59s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 59000), '287082'));
  it('RFC 6238 at T=1111111109s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 1111111109000), '081804'));
  it('RFC 6238 at T=1234567890s', () => assert.equal(Totp.codeAt(RFC_SECRET_B32, 1234567890000), '005924'));
});

describe('matchStep', () => {
  const t = 59000;
  it('returns the step for the current code', () => assert.equal(Totp.matchStep(RFC_SECRET_B32, '287082', t), 1));
  it('tolerates one step of clock drift either way', () => {
    assert.notEqual(Totp.matchStep(RFC_SECRET_B32, '287082', t + 30000), null);
    assert.notEqual(Totp.matchStep(RFC_SECRET_B32, '287082', t - 30000), null);
  });
  it('rejects codes two or more steps away', () => assert.equal(Totp.matchStep(RFC_SECRET_B32, '287082', t + 90000), null));
  it('rejects wrong, short and non-numeric codes', () => {
    assert.equal(Totp.matchStep(RFC_SECRET_B32, '000000', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, '123', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, 'abcdef', t), null);
    assert.equal(Totp.matchStep(RFC_SECRET_B32, undefined, t), null);
  });
});

describe('secret encryption', () => {
  it('encrypts and decrypts', () => {
    const enc = Totp.encrypt('SECRETVALUE');
    assert.notEqual(enc, 'SECRETVALUE');
    assert.equal(Totp.decrypt(enc), 'SECRETVALUE');
  });
  it('uses a fresh IV each time', () => assert.notEqual(Totp.encrypt('same'), Totp.encrypt('same')));
  it('rejects tampered ciphertext', () => {
    const parts = Totp.encrypt('SECRETVALUE').split('.');
    parts[2] = Buffer.from('tampered-bytes').toString('base64');
    assert.throws(() => Totp.decrypt(parts.join('.')));
  });
});

describe('recovery codes and setup link', () => {
  it('generates 8 unique codes and stores only hashes', () => {
    const { plain, hashes } = Totp.generateRecoveryCodes(8);
    assert.equal(plain.length, 8);
    assert.equal(new Set(plain).size, 8);
    plain.forEach((c, i) => {
      assert.match(c, /^[a-f0-9]{5}-[a-f0-9]{5}$/);
      assert.equal(hashes[i], Totp.hashRecovery(c));
      assert.ok(!hashes[i].includes(c.replace('-', '')));
    });
  });
  it('hashing ignores case and the dash', () => {
    assert.equal(Totp.hashRecovery('ABCDE-12345'), Totp.hashRecovery('abcde12345'));
  });
  it('builds an otpauth:// URL authenticator apps understand', () => {
    const url = Totp.otpauthUrl('JBSWY3DPEHPK3PXP', '+27110000002');
    assert.ok(url.startsWith('otpauth://totp/SafeReach%3A%2B27110000002?'));
    assert.match(url, /secret=JBSWY3DPEHPK3PXP/);
    assert.match(url, /digits=6/);
    assert.match(url, /period=30/);
  });
});
