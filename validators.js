// middleware/validators.js
// Whitelist RegEx patterns — same approach the group used on the APDS7311
// payments portal. Every field that comes from a request body gets checked
// against one of these before it touches the database.
const PATTERNS = {
  fullName: /^[A-Za-z\s'-]{2,60}$/,
  phoneNumber: /^\+?\d{9,15}$/,
  // 8-72 chars (bcrypt only uses the first 72 bytes): capital, digit, one of @$!%*?&
  password: /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,72}$/,
  destination: /^[\w\s,.'()/#-]{0,120}$/,
  description: /^[\w\s,.'()/#!?-]{1,1000}$/,
  latLng: /^-?\d{1,3}\.\d{1,10}$/,
  mongoId: /^[a-f0-9]{24}$/i,
  branchName: /^[A-Za-z0-9\s,.'()&-]{2,80}$/,
  region: /^[A-Za-z0-9\s,.'()&-]{2,60}$/,
};

// Only strings and numbers are ever valid. Arrays and objects are rejected
// outright — String(['+2782...']) would otherwise sneak past a regex test.
function isValid(pattern, value) {
  if (value === undefined || value === null) return false;
  if (typeof value !== 'string' && typeof value !== 'number') return false;
  return PATTERNS[pattern].test(String(value));
}

// validateBody({ fullName: 'fullName', ... }, ['fullName', ...])
//   1st argument: field -> pattern, checked when the field is present.
//   2nd argument (optional): fields that MUST be present. A missing required
//   field is now a 400 instead of slipping through and crashing later.
function validateBody(fieldMap, requiredFields = []) {
  return (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Request body must be a JSON object' });
    }
    for (const field of requiredFields) {
      const v = body[field];
      if (v === undefined || v === null || v === '') {
        return res.status(400).json({ error: `Missing required field: ${field}` });
      }
    }
    for (const [field, pattern] of Object.entries(fieldMap)) {
      const value = body[field];
      if (value === undefined) continue; // optional fields skip validation here
      if (!isValid(pattern, value)) {
        return res.status(400).json({ error: `Invalid format for field: ${field}` });
      }
    }
    next();
  };
}

// validateParams({ id: 'mongoId' }) — stops a bad :id reaching Mongoose,
// where it would throw a CastError and surface as a 500.
function validateParams(fieldMap) {
  return (req, res, next) => {
    for (const [field, pattern] of Object.entries(fieldMap)) {
      if (!isValid(pattern, req.params[field])) {
        return res.status(400).json({ error: `Invalid format for parameter: ${field}` });
      }
    }
    next();
  };
}

module.exports = { PATTERNS, isValid, validateBody, validateParams };
