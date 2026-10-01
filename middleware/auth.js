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

  let user;
  try {
    const decoded = AuthService.verifyToken(token);
    user = await UserRepository.findById(decoded.id);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });

    // Sessions issued before the last password change are no longer valid.
    if (user.passwordChangedAt && decoded.iat &&
        decoded.iat < Math.floor(user.passwordChangedAt.getTime() / 1000)) {
      return res.status(401).json({ error: 'Password was changed — please sign in again' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  // Deactivated accounts keep their records but can no longer use the API.
  if (user.active === false) {
    return res.status(401).json({ error: 'This account has been deactivated' });
  }

  req.user = user;
  next();
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
