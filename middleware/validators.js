// middleware/validators.js
// Whitelist RegEx patterns — same approach the group used on the APDS7311
// payments portal. Every field that comes from a request body gets checked
// against one of these before it touches the database.
const PATTERNS = {
  fullName: /^[A-Za-z\s'-]{2,60}$/,
  phoneNumber: /^\+?\d{9,15}$/,
  password: /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  destination: /^[\w\s,.'()/#-]{0,120}$/,
  description: /^[\w\s,.'()/#!?-]{1,1000}$/,
  latLng: /^-?\d{1,3}\.\d{1,10}$/,
  mongoId: /^[a-f0-9]{24}$/i,
};

function isValid(pattern, value) {
  if (value === undefined || value === null) return false;
  return PATTERNS[pattern].test(String(value));
}

// Express middleware factory — validateBody({ fullName: 'fullName', phoneNumber: 'phoneNumber' })
// checks req.body.fullName against PATTERNS.fullName, etc. Fields not listed
// are left alone (so this can be reused across routes with different shapes).
function validateBody(fieldMap) {
  return (req, res, next) => {
    for (const [field, pattern] of Object.entries(fieldMap)) {
      const value = req.body[field];
      if (value === undefined) continue; // optional fields skip validation here
      if (!isValid(pattern, value)) {
        return res.status(400).json({ error: `Invalid format for field: ${field}` });
      }
    }
    next();
  };
}

module.exports = { PATTERNS, isValid, validateBody };
