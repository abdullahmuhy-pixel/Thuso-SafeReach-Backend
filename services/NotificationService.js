// services/NotificationService.js
// Strategy pattern (Task 1, Section 4.1). This is the interface every
// notification channel must implement. The SOS route doesn't know or care
// whether it's talking to SMSNotifier or PushNotifier — it just calls
// send(alert), and picks a fallback if the first channel fails. This is
// what lets us cope with push notifications being unreliable on low-end
// Android devices without hard-coding a single delivery mechanism.
class NotificationService {
  // eslint-disable-next-line no-unused-vars
  async send(alert) {
    throw new Error('send() must be implemented by a concrete notifier');
  }
}

module.exports = NotificationService;
