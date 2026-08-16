# Thuso SafeReach — Backend (WIL 3, XADAD7112/w, Task 2)

Coordinator/admin backend for the Thuso SafeReach travel safety system. This
sits behind the existing SafeReach frontend PWA and adds the organisational
layer the frontend doesn't have on its own: accounts, a cloud database, a
coordinator dashboard, and a notification pipeline for SOS alerts.

## Why this structure

This maps directly onto the design decisions in Task 1 (Section 4) so the
patterns described there are actually visible in the code, not just in the
diagrams:

| Task 1 pattern | Where it lives |
|---|---|
| Repository (4.4) | `repositories/` — routes never touch Mongoose models directly |
| Strategy (4.1) | `services/NotificationService.js` + `SMSNotifier.js` + `PushNotifier.js` |
| Singleton (4.3) | `services/AuthService.js` |
| Observer-style live alerts (4.2) | `services/CheckInSweeper.js` polls for expired check-ins and pushes new `SOSAlert` records that the coordinator dashboard endpoint picks up |

## Setup

```bash
cp .env.example .env
# fill in MONGO_URI (MongoDB Atlas) and JWT_SECRET
npm install
npm run seed    # creates the first admin + coordinator account
npm run dev
```

## Accounts

- **Members** self-register via `POST /api/auth/register` — this is a public
  community app, so there's no reason to gate member sign-up.
- **Coordinators and admins** are pre-provisioned only. The seed script
  creates the very first admin account; after that, new coordinator/admin
  accounts are created by an existing admin through `POST /api/admin/users`.
  There is no public registration endpoint for these roles.

## Known limitations (honest — for the Task 2 report)

- Notification channels (`SMSNotifier`, `PushNotifier`) are stubbed until the
  group signs up for a real SMS gateway and configures Web Push. They log to
  the console and record a `Notification` row with `deliveryStatus: pending`
  so the data flow is testable end-to-end even before real credentials exist.
- `CheckInSweeper` polls every 30 seconds rather than using a proper job
  queue — fine at this scale, worth revisiting if this ever needed to run
  across multiple server instances.
- No automated test suite yet (`npm test` is a placeholder) — this is next
  on the list before the CircleCI pipeline can do more than lint.

## Endpoints

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | Public | Member self-registration |
| POST | `/api/auth/login` | Public | Member login |
| POST | `/api/coordinator/auth/login` | Public | Coordinator/admin login |
| POST | `/api/checkin` | Member | Start a check-in |
| PATCH | `/api/checkin/:id/extend` | Member | Extend an active check-in |
| PATCH | `/api/checkin/:id/safe` | Member | Cancel — "I'm safe" |
| POST | `/api/sos` | Member | Trigger an SOS alert (manual, shake, or check-in timeout) |
| GET | `/api/sos` | Coordinator/Admin | View active alerts |
| PATCH | `/api/sos/:id/resolve` | Coordinator/Admin | Resolve an alert |
| POST | `/api/incidents` | Member | Log an incident |
| GET | `/api/incidents` | Coordinator/Admin | View all incidents |
| GET | `/api/coordinator/dashboard` | Coordinator/Admin | Alerts + incidents summary |
| GET | `/api/admin/users` | Admin | List users |
| POST | `/api/admin/users` | Admin | Create a coordinator/admin/member account |
