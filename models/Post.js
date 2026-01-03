const mongoose = require("mongoose");

const MediaSchema = new mongoose.Schema({
  type: { type: String, enum: ["video", "image"], required: true },
  url: { type: String, required: true }
}, { _id: false });

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  username: { type: String, required: true, index: true },

  title: { type: String, default: "" },
  description: { type: String, default: "" },

  type: { type: String, enum: ["video", "carousel"], required: true },
  media: { type: [MediaSchema], required: true },

  likesCount: { type: Number, default: 0 },
  commentsCount: { type: Number, default: 0 },
  views: { type: Number, default: 0 },

  status: { type: String, default: "approved" }
}, { timestamps: true });

module.exports = mongoose.model("Post", PostSchema);
