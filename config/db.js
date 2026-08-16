// config/db.js — Cloud database connection (Task 1 requirement: cloud-based database)
const mongoose = require('mongoose');

async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error('[db] MONGO_URI is not set — check your .env file');
    process.exit(1);
  }

  try {
    await mongoose.connect(uri);
    console.log('[db] Connected to MongoDB Atlas');
  } catch (err) {
    console.error('[db] Connection failed:', err.message);
    process.exit(1);
  }

  mongoose.connection.on('disconnected', () => {
    console.warn('[db] MongoDB disconnected — attempting reconnect will be handled by the driver');
  });
}

module.exports = connectDB;
