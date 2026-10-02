// services/AuthService.js
// Singleton pattern (Task 1, Section 4.3). All JWT issuing and verification
// goes through this one instance rather than being reimplemented in each
// route file. With medical data in the system, we wanted exactly one place
// that decides "is this user allowed to see this" — not three slightly
// different versions of that check scattered around the codebase.
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// 12 in production. Tests set BCRYPT_ROUNDS=4 so hashing doesn't slow them down.
const SALT_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 12;

class AuthService {
  constructor() {
    if (AuthService._instance) {
      return AuthService._instance;
    }
    this.jwtSecret = process.env.JWT_SECRET;
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    AuthService._instance = this;
  }

  async hashPassword(plainPassword) {
    return bcrypt.hash(plainPassword, SALT_ROUNDS);
  }

  async verifyPassword(plainPassword, passwordHash) {
    return bcrypt.compare(plainPassword, passwordHash);
  }

  issueToken(user) {
    return jwt.sign(
      { id: user._id.toString(), role: user.role },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );
  }

  verifyToken(token) {
    return jwt.verify(token, this.jwtSecret);
  }

  // Short-lived token handed out after the password step of a 2FA login. It is
  // signed with a DIFFERENT key from session tokens, so it can never be used
  // to call the API — it only proves "this person already passed the password".
  issueChallengeToken(user) {
    return jwt.sign(
      { id: user._id.toString(), purpose: '2fa' },
      this.jwtSecret + ':2fa-challenge',
      { expiresIn: '5m' }
    );
  }

  verifyChallengeToken(token) {
    const decoded = jwt.verify(token, this.jwtSecret + ':2fa-challenge');
    if (decoded.purpose !== '2fa') throw new Error('Wrong token type');
    return decoded;
  }
}

// Freeze the single shared instance — every file that requires this module
// gets the same object back (Node's module cache already gives us this,
// but the constructor guard makes the intent explicit).
module.exports = new AuthService();
