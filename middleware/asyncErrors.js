// middleware/asyncErrors.js
// Express 4 does not catch errors thrown (or promises rejected) inside async
// route handlers. Without this, one bad request — for example bcrypt being
// handed an undefined password — becomes an unhandled promise rejection that
// can crash the whole server on current Node versions. This makes Express
// forward those failures to the central error handler in server.js instead.
// (Same approach as the `express-async-errors` package, no new dependency.)
let Layer = null;
try {
  Layer = require('express/lib/router/layer');
} catch (err) {
  console.warn('[asyncErrors] Could not patch the Express router:', err.message);
}

if (Layer && !Layer.prototype.__asyncErrorsPatched) {
  Layer.prototype.handle_request = function handle(req, res, next) {
    const fn = this.handle;
    if (fn.length > 3) return next(); // error-handling middleware: leave alone
    try {
      const out = fn(req, res, next);
      if (out && typeof out.catch === 'function') out.catch(next);
    } catch (err) {
      next(err);
    }
  };
  Layer.prototype.__asyncErrorsPatched = true;
}

// Last line of defence: log instead of dying if something still slips through.
process.on('unhandledRejection', (reason) => {
  console.error('[process] Unhandled rejection:', reason);
});
