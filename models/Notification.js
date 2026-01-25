const mongoose = require("mongoose");

const NotificationSchema = new mongoose.Schema(
  {
    userId: { // recipient (kimga keldi)
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    type: {
  type: String,
  enum: ["follow", "unfollow"],
  required: true,
  index: true
},


    actorId: { // kim qildi (kim follow qildi)
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    read: { type: Boolean, default: false, index: true }
  },
  { timestamps: true }
);

NotificationSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model("Notification", NotificationSchema);
