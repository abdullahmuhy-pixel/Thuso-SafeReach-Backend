// services/TotpService.js
// Time-based one-time passwords (RFC 6238) for coordinator/admin 2FA, built on
// Node's built-in crypto — no extra packages to install. Works with Google
// Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS and similar apps.
const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

// HOTP (RFC 4226): HMAC-SHA1 of the counter, dynamically truncated.
function hotp(key, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

const safeEqual = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

class TotpService {
  generateSecret() {
    return base32Encode(crypto.randomBytes(20)); // 160-bit secret, 32 base32 chars
  }

  codeAt(secretB32, timeMs = Date.now()) {
    return hotp(base32Decode(secretB32), Math.floor(timeMs / 1000 / STEP_SECONDS));
  }

  // Returns the matching 30-second step number, or null. Accepts one step
  // either side of "now" to tolerate clock drift between phone and server.
  matchStep(secretB32, code, timeMs = Date.now(), window = 1) {
    if (!/^\d{6}$/.test(String(code))) return null;
    const key = base32Decode(secretB32);
    const now = Math.floor(timeMs / 1000 / STEP_SECONDS);
    let found = null;
    for (let d = -window; d <= window; d++) {
      if (now + d < 0) continue; // no time step exists before 1970
      if (safeEqual(hotp(key, now + d), String(code)) && found === null) found = now + d;
    }
    return found;
  }

  otpauthUrl(secretB32, account, issuer = 'SafeReach') {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
  }

  // ── Secrets are encrypted at rest (AES-256-GCM). The key is derived from
  // JWT_SECRET, so rotating JWT_SECRET means 2FA must be re-enrolled
  // (an admin can reset it from the dashboard).
  _key() {
    return crypto.createHash('sha256').update('safereach-totp-key:' + process.env.JWT_SECRET).digest();
  }

  encrypt(plain) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this._key(), iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.');
  }

  decrypt(stored) {
    const [iv, tag, ct] = String(stored).split('.').map(p => Buffer.from(p, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', this._key(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  }

  // One-time recovery codes for a lost phone. Only SHA-256 hashes are stored.
  generateRecoveryCodes(count = 8) {
    const plain = [], hashes = [];
    for (let i = 0; i < count; i++) {
      const raw = crypto.randomBytes(5).toString('hex'); // 10 hex chars
      plain.push(raw.slice(0, 5) + '-' + raw.slice(5));
      hashes.push(this.hashRecovery(raw));
    }
    return { plain, hashes };
  }

  hashRecovery(code) {
    return crypto.createHash('sha256').update(String(code).replace(/[\s-]/g, '').toLowerCase()).digest('hex');
  }
}

module.exports = new TotpService();
module.exports._internals = { base32Encode, base32Decode, hotp };
