# Thuso SafeReach — Backend (WIL 3, XADAD7112/w, Task 2)

Backend for the Thuso SafeReach travel safety system, built for the fictional
NGO Thuso Travel Safety Network. It is a REST API (Node.js, Express, MongoDB
Atlas) that sits behind two web pages in this repository: the member app
(`index.html`, a PWA) and the coordinator/admin dashboard (`coordinator.html`).

## Live system

| Part | Address |
|---|---|
| Member app | https://abdullahmuhy-pixel.github.io/Thuso-SafeReach-Backend/ |
| Dashboard | https://abdullahmuhy-pixel.github.io/Thuso-SafeReach-Backend/coordinator.html |
| API health check | https://thuso-safereach-backend.onrender.com/api/health |

The API runs on a free Render instance that sleeps when idle, so the first
request after a quiet period can take up to a minute. No sign-in details are
kept in this repository.

## What it does

- Members register, start a check-in timer, send an SOS (button or shake) and
  log incidents.
- If a check-in runs out unconfirmed, the server raises an SOS alert by itself
  (`services/CheckInSweeper.js`, every 30 seconds).
- Coordinators see and resolve alerts and review incidents for their branch.
- Admins also manage accounts, roles, branches, deactivation, password resets
  and two-factor resets.
- Optional two-factor authentication (RFC 6238) for coordinators and admins.

## Structure and design patterns

| Pattern | Where it lives |
|---|---|
| Repository | `repositories/` — routes never touch Mongoose models directly |
| Strategy | `services/NotificationService.js` with `SMSNotifier.js` and `PushNotifier.js` |
| Singleton | `services/AuthService.js` |
| Observer (replaced) | The dashboard polls every 15 seconds instead of subscribing to events |

Other folders: `routes/`, `middleware/`, `models/`, `config/`, `seed/`, `tests/`.

## Setup

```
cp .env.example .env
# fill in MONGO_URI (MongoDB Atlas) and JWT_SECRET
npm install
npm run seed    # creates the first admin and coordinator
npm run dev
```

The seed script holds no passwords. Set `SEED_ADMIN_PASSWORD` and
`SEED_COORDINATOR_PASSWORD` in `.env`, or leave them out and a random
one-time password is printed once in the terminal. Change it after first
sign-in.

## Tests and CI

```
npm test
```

The automated suite (142 tests) starts the real Express app and sends real
HTTP requests, with in-memory repositories instead of a database, so it needs
no database and no secrets. It uses Node's built-in test runner. It covers
validation, accounts and sessions, check-ins, SOS, incidents, coordinator and
admin features, branch scoping, two-factor login and error handling. See
`tests/README.md`.

CircleCI runs `npm test` on every push to `main` (`.circleci/config.yml`).
Render redeploys the API and GitHub Pages republishes the pages.

## Accounts

- Members self-register through `POST /api/auth/register`.
- Coordinators and admins have no public registration. The seed script creates
  the first ones; after that an admin creates them through the Users tab or
  `POST /api/admin/users`. They sign in through a separate login so two-factor
  authentication cannot be skipped.

## Main endpoints

| Area | Endpoints | Who |
|---|---|---|
| Auth | `/api/auth/register`, `/login`, `PATCH /password` | Member / any signed-in user |
| Staff auth | `/api/coordinator/auth/login`, `/verify-2fa`, `/2fa/setup`, `/enable`, `/disable` | Coordinator, admin |
| Check-in | `POST /api/checkin`, `GET /active`, `PATCH /:id/extend`, `/:id/safe` | Member |
| SOS | `POST /api/sos`; `GET /api/sos`, `PATCH /:id/resolve` | Member; coordinator, admin |
| Incidents | `POST /api/incidents`, `GET /mine`; `GET /api/incidents`, `PATCH /:id/review` | Member; coordinator, admin |
| Dashboard | `GET /api/coordinator/dashboard`, `/members` | Coordinator, admin |
| Admin | `/api/admin/users` (create, role, active, branch, reset-password, reset-2fa), `/api/admin/branches` | Admin |
| Health | `GET /api/health` | Public |

## Security notes

Passwords are hashed with bcrypt (12 rounds); sessions are signed tokens that
last one hour and stop working after a password change; every field is
checked against a whitelist pattern; errors return a generic message; secrets
live in environment variables, never in the repository.

## Known limitations

- SMS and push senders are stubs that only log; no provider is connected.
- The dashboard refreshes every 15 seconds, so the 5-second alert target from
  Task 1 is not met. Server-sent events or WebSockets would fix this.
- The free hosting tier sleeps when idle.
- Medical ID and trip plans stay on the phone and are not synced.
- Two-factor setup uses a typed key; there is no QR code.
- Members cannot choose their own branch; an admin assigns it.
- Temporary passwords are not forced to change on first sign-in.
- The real MongoDB queries are not run by the automated tests.
