// middleware/auth.js
// JWT verification + role-based access control. Uses the AuthService
// singleton (services/AuthService.js) rather than calling jsonwebtoken
// directly, so token handling logic lives in exactly one place.
const AuthService = require('../services/AuthService');
const UserRepository = require('../repositories/UserRepository');

// Verifies the JWT and attaches req.user. Does not check role — use
// requireRole() after this for role-specific routes.
async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.cookies?.token;

  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = AuthService.verifyToken(token);
    const user = await UserRepository.findById(decoded.id);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// requireRole('coordinator', 'admin') — call after authenticate()
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden — insufficient role' });
    }
    next();
  };
}

module.exports = { authenticate, requireRole };
