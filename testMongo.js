require('dotenv').config();
const mongoose = require('mongoose');

(async () => {
  try {
    console.log('Connecting to:', process.env.MONGO_URI);
await mongoose.connect(process.env.MONGO_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
});
    console.log('MongoDB CONNECTED SUCCESSFULLY');
    process.exit(0);
  } catch (e) {
    console.error('MongoDB FAILED:', e.message);
    process.exit(1);
  }
})();
