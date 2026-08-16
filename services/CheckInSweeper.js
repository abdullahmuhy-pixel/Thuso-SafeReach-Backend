// services/CheckInSweeper.js
// The SafeReach frontend times its own check-in countdown client-side, but
// that only works while the app is open (see the note in the check-in
// overlay UI). This sweep runs server-side every 30 seconds and catches
// any check-in that expired while the member's app was closed or their
// phone was offline, so escalation doesn't depend on the client being alive.
const CheckInRepository = require('../repositories/CheckInRepository');
const SOSAlertRepository = require('../repositories/SOSAlertRepository');
const IncidentRepository = require('../repositories/IncidentRepository');
const { dispatchAlert } = require('./NotificationDispatcher');

const SWEEP_INTERVAL_MS = 30 * 1000;
let sweepTimer = null;

async function sweepOnce() {
  const expired = await CheckInRepository.findAllExpiredActive();
  for (const checkIn of expired) {
    await CheckInRepository.markEscalated(checkIn._id);

    const alert = await SOSAlertRepository.create({
      userId: checkIn.userId,
      checkInId: checkIn._id,
      triggerSource: 'checkin_timeout',
      lat: checkIn.lat,
      lng: checkIn.lng,
    });

    await IncidentRepository.create({
      userId: checkIn.userId,
      type: 'checkin',
      description: `Check-in "${checkIn.destination || 'trip'}" (${checkIn.durationMinutes} min) expired without confirmation.`,
      severity: 'high',
      location: checkIn.lat ? `${checkIn.lat}, ${checkIn.lng}` : 'Location not set',
      lat: checkIn.lat,
      lng: checkIn.lng,
    });

    await dispatchAlert(alert);
    console.log(`[CheckInSweeper] Escalated check-in ${checkIn._id} -> alert ${alert._id}`);
  }
}

function start() {
  if (sweepTimer) return;
  sweepTimer = setInterval(() => {
    sweepOnce().catch(err => console.error('[CheckInSweeper] Sweep failed:', err.message));
  }, SWEEP_INTERVAL_MS);
  console.log('[CheckInSweeper] Started — checking for expired check-ins every 30s');
}

function stop() {
  if (sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = null;
  }
}

module.exports = { start, stop, sweepOnce };
