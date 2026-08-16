// services/PushNotifier.js — concrete Strategy implementation
// Stubbed for Task 2 until the group wires up Web Push (e.g. via a service
// worker push subscription) for the coordinator dashboard.
const NotificationService = require('./NotificationService');

class PushNotifier extends NotificationService {
  async send(alert) {
    const apiKey = process.env.PUSH_SERVICE_API_KEY;
    if (!apiKey) {
      console.log(`[PushNotifier] (stub — no PUSH_SERVICE_API_KEY set) Would push-notify coordinators about alert ${alert._id}`);
      return { channel: 'push', deliveryStatus: 'pending' };
    }
    console.log(`[PushNotifier] Sending push notification for alert ${alert._id}`);
    return { channel: 'push', deliveryStatus: 'sent' };
  }
}

module.exports = PushNotifier;
