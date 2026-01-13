const mongoose = require("mongoose");

async function connectDB() {
  const mongoUri = process.env.MONGO_URI_APP || process.env.MONGO_URI;

  if (!mongoUri) {
    console.error("FATAL: No MongoDB URI provided");
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri, {
      maxPoolSize: 20,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      retryWrites: true
    });

    console.log("MongoDB Atlas connected");
  } catch (err) {
    console.error("Initial MongoDB connection error:", err.message);
  }

  mongoose.connection.on("disconnected", () => {
    console.warn("MongoDB disconnected, attempting reconnect...");
  });

  mongoose.connection.on("error", (err) => {
    console.error("MongoDB runtime error:", err.message);
  });
}

module.exports = connectDB;
