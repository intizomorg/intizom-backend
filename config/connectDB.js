const mongoose = require("mongoose");

async function connectDB() {
  try {
    const mongoUri =
      process.env.MONGO_URI_APP || process.env.MONGO_URI;

    if (!mongoUri) {
      console.error("FATAL: No MongoDB URI provided");
      process.exit(1);
    }

    await mongoose.connect(mongoUri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    });

    console.log("MongoDB Atlas connected");
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    process.exit(1);
  }
}

module.exports = connectDB;
