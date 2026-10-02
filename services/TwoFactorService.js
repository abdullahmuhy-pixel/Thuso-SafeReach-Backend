// services/TwoFactorService.js — verifies a 2FA code (authenticator code or
// one-time recovery code) with replay protection and a lockout after repeated
// failures, so the 6-digit code cannot be brute-forced.
const TotpService = require('./TotpService');
const UserRepository = require('../repositories/UserRepository');

const FAIL_LIMIT = 5;
const LOCK_MS = 15 * 60 * 1000;

// `user` must be loaded with the 2FA fields (UserRepository.findByIdWith2FA).
async function verifyForUser(user, rawInput, now = Date.now()) {
  if (user.totpLockedUntil && new Date(user.totpLockedUntil).getTime() > now) {
    return { ok: false, reason: 'locked' };
  }

  const input = typeof rawInput === 'string' ? rawInput.replace(/[\s-]/g, '') : '';
  let ok = false;

  if (/^\d{6}$/.test(input)) {
    const step = TotpService.matchStep(TotpService.decrypt(user.totpSecret), input, now);
    // claimTotpStep is atomic: a code can only be used once, even if two
    // requests arrive at the same moment.
    ok = step !== null && await UserRepository.claimTotpStep(user._id, step);
  } else if (/^[a-f0-9]{10}$/i.test(input)) {
    ok = await UserRepository.consumeRecoveryHash(user._id, TotpService.hashRecovery(input));
  }

  if (ok) {
    await UserRepository.resetTotpFailures(user._id);
    return { ok: true };
  }
  const locked = await UserRepository.recordTotpFailure(user._id, FAIL_LIMIT, LOCK_MS);
  return { ok: false, reason: locked ? 'locked' : 'invalid' };
}

module.exports = { verifyForUser, FAIL_LIMIT, LOCK_MS };
