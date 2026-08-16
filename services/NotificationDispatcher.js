// services/NotificationDispatcher.js
// Picks a notification Strategy at runtime and logs the attempt to the
// Notification collection (Task 1 ER diagram — NOTIFICATION entity).
// If the preferred channel fails, it falls back to the other one, which is
// the whole point of using the Strategy pattern here instead of a single
// hard-coded delivery path.
const PushNotifier = require('./PushNotifier');
const SMSNotifier = require('./SMSNotifier');
const Notification = require('../models/Notification');

const push = new PushNotifier();
const sms = new SMSNotifier();

async function dispatchAlert(alert, { preferred = 'push' } = {}) {
  const primary = preferred === 'sms' ? sms : push;
  const fallback = preferred === 'sms' ? push : sms;

  let result;
  try {
    result = await primary.send(alert);
    if (result.deliveryStatus === 'failed') throw new Error('primary channel failed');
  } catch (err) {
    console.warn(`[NotificationDispatcher] Primary channel failed (${err.message}), falling back`);
    result = await fallback.send(alert);
  }

  await Notification.create({
    alertId: alert._id,
    channel: result.channel,
    deliveryStatus: result.deliveryStatus,
  });

  return result;
}

module.exports = { dispatchAlert };
