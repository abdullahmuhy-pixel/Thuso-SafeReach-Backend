# Automated tests

Run everything with:

```
npm test
```

CircleCI runs the same command on every push to `main` (see `.circleci/config.yml`).
The tests use Node's built-in test runner — no extra packages needed.

## How they work

Most tests start the **real** Express app (`server.js`: the real middleware, routes,
JWT, bcrypt and error handler) on a random port and talk to it over HTTP. Only the
data layer is swapped for in-memory fakes (`tests/helpers/fakes.js`), which is what the
repository pattern from the Task 1 design makes possible — so no MongoDB connection
or `.env` file is needed.

| File | What it covers |
|---|---|
| `validators.test.js` | Whitelist input validation (patterns, required fields, bad ids, arrays/objects) |
| `totp.test.js` | 2FA maths against the official RFC 4226 / RFC 6238 test vectors, secret encryption, recovery codes |
| `auth.api.test.js` | Register, login, password change, session revocation, deactivated accounts |
| `members.api.test.js` | Check-ins, SOS alerts, incident reports, role separation |
| `coordinator.api.test.js` | Dashboard, resolving alerts, reviewing incidents, the check-in sweeper |
| `branches.api.test.js` | Branch-scoped visibility: who sees which alerts, incident reports and members; routing by the member's branch |
| `admin.api.test.js` | Accounts, roles, branches, deactivate/reactivate, password reset |
| `twofactor.api.test.js` | Two-step login, recovery codes, replay and brute-force protection, resets |
| `errors.api.test.js` | Malformed input and internal failures never crash the server or leak internals |
| `models.test.js` | Mongoose schema rules and that secrets are never serialised (needs no database) |

## Not covered

The real Mongoose queries inside `repositories/` are not exercised here — that would need
a database (for example `mongodb-memory-server`). The tests prove the API logic around them.
