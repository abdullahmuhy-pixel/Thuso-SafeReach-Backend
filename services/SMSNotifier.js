// services/SMSNotifier.js — concrete Strategy implementation
// Stubbed for Task 2 until the group signs up for a real SMS gateway
// (e.g. Twilio, Africa's Talking). The interface is what matters here —
// swapping this out for a real provider later doesn't touch any route code.
const NotificationService = require('./NotificationService');

class SMSNotifier extends NotificationService {
  async send(alert) {
    const apiKey = process.env.SMS_GATEWAY_API_KEY;
    if (!apiKey) {
      console.log(`[SMSNotifier] (stub — no SMS_GATEWAY_API_KEY set) Would SMS coordinators about alert ${alert._id}`);
      return { channel: 'sms', deliveryStatus: 'pending' };
    }
    // Real implementation would call the SMS gateway's REST API here.
    console.log(`[SMSNotifier] Sending SMS for alert ${alert._id}`);
    return { channel: 'sms', deliveryStatus: 'sent' };
  }
}

module.exports = SMSNotifier;
