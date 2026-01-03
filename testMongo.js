require('dotenv').config();
const mongoose = require('mongoose');

(async () => {
  try {
    console.log('Connecting to:', process.env.MONGO_URI);
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB CONNECTED SUCCESSFULLY');
    process.exit(0);
  } catch (e) {
    console.error('MongoDB FAILED:', e.message);
    process.exit(1);
  }
})();
