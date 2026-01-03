const mongoose = require("mongoose");

async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error("MONGO_URI env o‘rnatilmagan");
    process.exit(1);
  }

  try {
    await mongoose.connect(uri, {
      autoIndex: false,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    console.log("MongoDB ulandi");
  } catch (err) {
    console.error("MongoDB ulanish xatosi:", err.message);
    process.exit(1);
  }
}

module.exports = connectDB;
